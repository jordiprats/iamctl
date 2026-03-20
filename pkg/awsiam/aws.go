package awsiam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/policy"
)

// IAMClient is the subset of the IAM API used by this package.
type IAMClient interface {
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
}

// RoleDescription is a detailed role view for describe-role style output.
type RoleDescription struct {
	RoleName           string
	ARN                string
	CreateDate         time.Time
	SwitchRoleURL      string
	LastUsedAt         *time.Time
	MaxSessionDuration int32
	AttachedPolicies   []AttachedPolicyRef
	InlinePolicies     map[string]policy.PolicyDocument
}

// PolicyDescription is a detailed managed policy view for describe-policy style output.
type PolicyDescription struct {
	Name             string
	ARN              string
	Description      string
	Path             string
	DefaultVersionID string
	CreateDate       *time.Time
	UpdateDate       *time.Time
	IsAWSManaged     bool
	Document         policy.PolicyDocument
}

// AttachedPolicyRef is a managed policy attached to a role.
type AttachedPolicyRef struct {
	Name string `json:"name"`
	ARN  string `json:"arn"`
}

// RoleSummary represents a minimal role identity.
type RoleSummary struct {
	Name       string     `json:"name"`
	ARN        string     `json:"arn"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// ManagedPolicySummary represents a minimal managed policy identity.
type ManagedPolicySummary struct {
	Name        string `json:"name"`
	ARN         string `json:"arn"`
	Description string `json:"description,omitempty"`
}

// RoleSearchFilters defines optional filters for role listing.
type RoleSearchFilters struct {
	LastActiveAfter *time.Time
}

// PolicySearchFilters defines optional filters for managed policy listing.
type PolicySearchFilters struct {
	DescriptionContains    string
	DescriptionNotContains string
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
func FetchRoleBoundary(ctx context.Context, client IAMClient, roleName string) (*boundary.PermissionBoundary, error) {
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

	return &boundary.PermissionBoundary{
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

// FetchRoleInlinePolicies lists and fetches all inline policies for a role.
// Returns a map of policy name -> parsed PolicyDocument.
func FetchRoleInlinePolicies(ctx context.Context, client IAMClient, roleName string) (map[string]policy.PolicyDocument, error) {
	var names []string
	var marker *string
	for {
		out, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: &roleName,
			Marker:   marker,
		})
		if err != nil {
			return nil, fmt.Errorf("listing inline policies for role %q: %w", roleName, err)
		}
		names = append(names, out.PolicyNames...)
		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}

	result := make(map[string]policy.PolicyDocument, len(names))
	for _, name := range names {
		n := name
		out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &n,
		})
		if err != nil {
			return nil, fmt.Errorf("getting inline policy %q for role %q: %w", name, roleName, err)
		}
		docStr, err := url.QueryUnescape(*out.PolicyDocument)
		if err != nil {
			return nil, fmt.Errorf("decoding inline policy %q for role %q: %w", name, roleName, err)
		}
		var doc policy.PolicyDocument
		if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
			return nil, fmt.Errorf("parsing inline policy %q for role %q: %w", name, roleName, err)
		}
		result[name] = doc
	}
	return result, nil
}

// FetchManagedPolicyAsBoundary fetches a managed policy by ARN and returns it as a PermissionBoundary.
func FetchManagedPolicyAsBoundary(ctx context.Context, client IAMClient, policyARN string) (*boundary.PermissionBoundary, error) {
	doc, err := FetchManagedPolicy(ctx, client, policyARN)
	if err != nil {
		return nil, err
	}
	return &boundary.PermissionBoundary{
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

// DescribeRole returns role summary plus managed and inline policies.
func DescribeRole(ctx context.Context, client IAMClient, roleName string) (*RoleDescription, error) {
	roleOut, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if err != nil {
		return nil, fmt.Errorf("getting role %q: %w", roleName, err)
	}
	if roleOut.Role == nil || roleOut.Role.Arn == nil || roleOut.Role.RoleName == nil || roleOut.Role.CreateDate == nil {
		return nil, fmt.Errorf("role %q response missing required fields", roleName)
	}

	desc := &RoleDescription{
		RoleName:           *roleOut.Role.RoleName,
		ARN:                *roleOut.Role.Arn,
		CreateDate:         *roleOut.Role.CreateDate,
		MaxSessionDuration: 3600,
		InlinePolicies:     map[string]policy.PolicyDocument{},
	}
	if roleOut.Role.MaxSessionDuration != nil {
		desc.MaxSessionDuration = *roleOut.Role.MaxSessionDuration
	}
	if roleOut.Role.RoleLastUsed != nil && roleOut.Role.RoleLastUsed.LastUsedDate != nil {
		v := *roleOut.Role.RoleLastUsed.LastUsedDate
		desc.LastUsedAt = &v
	}

	accountID := extractAccountIDFromRoleARN(desc.ARN)
	if accountID != "" {
		desc.SwitchRoleURL = fmt.Sprintf(
			"https://signin.aws.amazon.com/switchrole?roleName=%s&account=%s",
			url.QueryEscape(desc.RoleName),
			url.QueryEscape(accountID),
		)
	}

	var attached []AttachedPolicyRef
	var marker *string
	for {
		out, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &roleName, Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listing attached policies for role %q: %w", roleName, err)
		}
		for _, p := range out.AttachedPolicies {
			if p.PolicyName != nil && p.PolicyArn != nil {
				attached = append(attached, AttachedPolicyRef{Name: *p.PolicyName, ARN: *p.PolicyArn})
			}
		}
		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}
	sort.Slice(attached, func(i, j int) bool {
		return attached[i].Name < attached[j].Name
	})
	desc.AttachedPolicies = attached

	var inlineNames []string
	marker = nil
	for {
		out, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &roleName, Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listing inline policies for role %q: %w", roleName, err)
		}
		inlineNames = append(inlineNames, out.PolicyNames...)
		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}
	sort.Strings(inlineNames)

	for _, policyName := range inlineNames {
		out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: &policyName})
		if err != nil {
			return nil, fmt.Errorf("getting inline policy %q for role %q: %w", policyName, roleName, err)
		}
		if out.PolicyDocument == nil {
			continue
		}
		docStr, err := url.QueryUnescape(*out.PolicyDocument)
		if err != nil {
			return nil, fmt.Errorf("decoding inline policy %q for role %q: %w", policyName, roleName, err)
		}
		var doc policy.PolicyDocument
		if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
			return nil, fmt.Errorf("parsing inline policy %q for role %q: %w", policyName, roleName, err)
		}
		desc.InlinePolicies[policyName] = doc
	}

	return desc, nil
}

// DescribeManagedPolicy returns managed policy metadata and default version document.
func DescribeManagedPolicy(ctx context.Context, client IAMClient, policyARN string) (*PolicyDescription, error) {
	policyOut, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &policyARN})
	if err != nil {
		return nil, fmt.Errorf("getting policy %q: %w", policyARN, err)
	}
	if policyOut.Policy == nil || policyOut.Policy.DefaultVersionId == nil || policyOut.Policy.PolicyName == nil || policyOut.Policy.Arn == nil {
		return nil, fmt.Errorf("policy %q response missing required fields", policyARN)
	}

	versionOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: &policyARN, VersionId: policyOut.Policy.DefaultVersionId})
	if err != nil {
		return nil, fmt.Errorf("getting policy version for %q: %w", policyARN, err)
	}
	if versionOut.PolicyVersion == nil || versionOut.PolicyVersion.Document == nil {
		return nil, fmt.Errorf("policy version for %q missing document", policyARN)
	}

	docStr, err := url.QueryUnescape(*versionOut.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("decoding policy document for %q: %w", policyARN, err)
	}
	var doc policy.PolicyDocument
	if err := json.Unmarshal([]byte(docStr), &doc); err != nil {
		return nil, fmt.Errorf("parsing policy document for %q: %w", policyARN, err)
	}

	desc := &PolicyDescription{
		Name:             *policyOut.Policy.PolicyName,
		ARN:              *policyOut.Policy.Arn,
		DefaultVersionID: *policyOut.Policy.DefaultVersionId,
		Document:         doc,
		IsAWSManaged:     strings.Contains(*policyOut.Policy.Arn, ":iam::aws:policy/"),
	}
	if policyOut.Policy.Description != nil {
		desc.Description = *policyOut.Policy.Description
	}
	if policyOut.Policy.Path != nil {
		desc.Path = *policyOut.Policy.Path
	}
	if policyOut.Policy.CreateDate != nil {
		v := *policyOut.Policy.CreateDate
		desc.CreateDate = &v
	}
	if policyOut.Policy.UpdateDate != nil {
		v := *policyOut.Policy.UpdateDate
		desc.UpdateDate = &v
	}

	return desc, nil
}

func extractAccountIDFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

// SearchRolesBySubstring lists account roles whose names contain query, case-insensitively.
func SearchRolesBySubstring(ctx context.Context, client IAMClient, query string, filters RoleSearchFilters) ([]RoleSummary, error) {
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" {
		return nil, fmt.Errorf("query must not be empty")
	}

	var roles []RoleSummary
	var marker *string
	for {
		out, err := client.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listing IAM roles: %w", err)
		}

		for _, role := range out.Roles {
			if role.RoleName == nil || role.Arn == nil {
				continue
			}
			if strings.Contains(strings.ToLower(*role.RoleName), needle) {
				var lastUsedAt *time.Time
				if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
					v := *role.RoleLastUsed.LastUsedDate
					lastUsedAt = &v
				}

				if filters.LastActiveAfter != nil {
					if lastUsedAt == nil || lastUsedAt.Before(*filters.LastActiveAfter) {
						continue
					}
				}

				roles = append(roles, RoleSummary{Name: *role.RoleName, ARN: *role.Arn, LastUsedAt: lastUsedAt})
			}
		}

		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}

	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Name < roles[j].Name
	})

	return roles, nil
}

// SearchManagedPoliciesBySubstring lists managed policies whose names contain query, case-insensitively.
// Scope can be "All", "AWS", or "Local".
func SearchManagedPoliciesBySubstring(ctx context.Context, client IAMClient, query string, scope iamtypes.PolicyScopeType, filters PolicySearchFilters) ([]ManagedPolicySummary, error) {
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" {
		return nil, fmt.Errorf("query must not be empty")
	}
	containsNeedle := strings.ToLower(strings.TrimSpace(filters.DescriptionContains))
	notContainsNeedle := strings.ToLower(strings.TrimSpace(filters.DescriptionNotContains))

	var policies []ManagedPolicySummary
	var marker *string
	for {
		out, err := client.ListPolicies(ctx, &iam.ListPoliciesInput{Marker: marker, Scope: scope})
		if err != nil {
			return nil, fmt.Errorf("listing IAM managed policies: %w", err)
		}

		for _, p := range out.Policies {
			if p.PolicyName == nil || p.Arn == nil {
				continue
			}
			if strings.Contains(strings.ToLower(*p.PolicyName), needle) {
				description := ""
				if p.Description != nil {
					description = *p.Description
				}

				lowerDesc := strings.ToLower(description)
				if containsNeedle != "" && !strings.Contains(lowerDesc, containsNeedle) {
					continue
				}
				if notContainsNeedle != "" && strings.Contains(lowerDesc, notContainsNeedle) {
					continue
				}

				policies = append(policies, ManagedPolicySummary{Name: *p.PolicyName, ARN: *p.Arn, Description: description})
			}
		}

		if !out.IsTruncated {
			break
		}
		marker = out.Marker
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})

	return policies, nil
}
