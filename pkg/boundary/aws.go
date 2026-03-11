package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/jordiprats/iam-pb-check/pkg/policy"
)

// NewIAMClient creates an IAM client using the given profile (or default credentials).
func NewIAMClient(ctx context.Context, profile string) (*iam.Client, error) {
	var opts []func(*config.LoadOptions) error
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return iam.NewFromConfig(cfg), nil
}

// FetchRoleBoundary fetches the permission boundary attached to a role via the AWS API.
func FetchRoleBoundary(ctx context.Context, client *iam.Client, roleName string) (*PermissionBoundary, error) {
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
func FetchRolePolicies(ctx context.Context, client *iam.Client, roleName string) (map[string]policy.PolicyDocument, error) {
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
		// Get default version ID
		policyOut, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: &p.ARN,
		})
		if err != nil {
			return nil, fmt.Errorf("getting policy %q: %w", p.ARN, err)
		}

		versionID := policyOut.Policy.DefaultVersionId

		// Get the policy document
		versionOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: &p.ARN,
			VersionId: versionID,
		})
		if err != nil {
			return nil, fmt.Errorf("getting policy version for %q: %w", p.ARN, err)
		}

		// Policy document is URL-encoded
		docStr, err := url.QueryUnescape(*versionOut.PolicyVersion.Document)
		if err != nil {
			return nil, fmt.Errorf("decoding policy document for %q: %w", p.Name, err)
		}

		var doc policy.PolicyDocument
		if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
			return nil, fmt.Errorf("parsing policy document for %q: %w", p.Name, err)
		}

		result[p.Name] = doc
	}

	return result, nil
}
