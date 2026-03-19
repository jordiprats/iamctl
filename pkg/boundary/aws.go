package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jordiprats/iam-pb-check/pkg/policy"
)

// IAMClient is the subset of the IAM API used by this package.
type IAMClient interface {
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
}

// NewIAMClient creates an IAM client using the given profile (or default credentials).
func NewIAMClient(ctx context.Context, profile string) (IAMClient, error) {
	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRetryMode(aws.RetryModeAdaptive))
	opts = append(opts, config.WithRetryMaxAttempts(10))
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return iam.NewFromConfig(cfg), nil
}

// GetAWSPseudoParams fetches AWS pseudo-parameter values (AccountId, Region)
// using the current credentials. Returns a map suitable for cfn.ResolveIntrinsic.
func GetAWSPseudoParams(ctx context.Context, profile string) (map[string]string, error) {
	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRetryMode(aws.RetryModeAdaptive))
	opts = append(opts, config.WithRetryMaxAttempts(10))
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("getting caller identity: %w", err)
	}

	params := map[string]string{
		"AWS::AccountId": *identity.Account,
		"AWS::Region":    cfg.Region,
	}
	return params, nil
}

// FetchRoleBoundary fetches the permission boundary attached to a role via the AWS API.
func FetchRoleBoundary(ctx context.Context, client IAMClient, roleName string) (*PermissionBoundary, error) {
	roleOut, err := client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("getting role %q: %w", roleName, err)
	}

	if roleOut.Role.PermissionsBoundary == nil {
		return nil, fmt.Errorf("role %q has no permission boundary configured", roleName)
	}

	pbArn := *roleOut.Role.PermissionsBoundary.PermissionsBoundaryArn
	fmt.Fprintf(os.Stderr, "Using permission boundary from role: %s\n", pbArn)

	// Get the policy's default version
	policyOut, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &pbArn,
	})
	if err != nil {
		return nil, fmt.Errorf("getting permission boundary policy %q: %w", pbArn, err)
	}

	versionOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &pbArn,
		VersionId: policyOut.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, fmt.Errorf("getting permission boundary policy version: %w", err)
	}

	docStr, err := url.QueryUnescape(*versionOut.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("decoding permission boundary document: %w", err)
	}

	var doc policy.PolicyDocument
	if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
		return nil, fmt.Errorf("parsing permission boundary document: %w", err)
	}

	return &PermissionBoundary{
		Policy:           &doc,
		EvaluationMethod: "Full IAM policy evaluation",
	}, nil
}

// FetchRolePolicies lists attached managed policies for a role and fetches each policy document.
func FetchRolePolicies(ctx context.Context, client IAMClient, roleName string) (map[string]policy.PolicyDocument, error) {
	var policyARNs []struct {
		ARN  string
		Name string
	}
	var marker *string
	for {
		out, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: &roleName,
			Marker:   marker,
		})
		if err != nil {
			return nil, fmt.Errorf("listing attached policies for role %q: %w", roleName, err)
		}
		for _, p := range out.AttachedPolicies {
			policyARNs = append(policyARNs, struct {
				ARN  string
				Name string
			}{ARN: *p.PolicyArn, Name: *p.PolicyName})
		}
		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}

	result := make(map[string]policy.PolicyDocument, len(policyARNs))
	for _, p := range policyARNs {
		doc, err := FetchManagedPolicy(ctx, client, p.ARN)
		if err != nil {
			return nil, err
		}
		result[p.Name] = *doc
	}

	return result, nil
}

// FetchManagedPolicyAsBoundary fetches a managed policy by ARN and returns it as a PermissionBoundary.
func FetchManagedPolicyAsBoundary(ctx context.Context, client IAMClient, policyARN string) (*PermissionBoundary, error) {
	doc, err := FetchManagedPolicy(ctx, client, policyARN)
	if err != nil {
		return nil, err
	}
	return &PermissionBoundary{
		Policy:           doc,
		EvaluationMethod: "Full IAM policy evaluation",
	}, nil
}

// FetchManagedPolicy fetches the default version of a managed policy by ARN and returns its document.
func FetchManagedPolicy(ctx context.Context, client IAMClient, policyARN string) (*policy.PolicyDocument, error) {
	policyOut, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &policyARN,
	})
	if err != nil {
		return nil, fmt.Errorf("getting policy %q: %w", policyARN, err)
	}

	versionOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyARN,
		VersionId: policyOut.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, fmt.Errorf("getting policy version for %q: %w", policyARN, err)
	}

	docStr, err := url.QueryUnescape(*versionOut.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("decoding policy document for %q: %w", policyARN, err)
	}

	var doc policy.PolicyDocument
	if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
		return nil, fmt.Errorf("parsing policy document for %q: %w", policyARN, err)
	}

	return &doc, nil
}
