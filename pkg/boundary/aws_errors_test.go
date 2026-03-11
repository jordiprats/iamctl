package boundary

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestFetchManagedPolicy_GetPolicyVersionError(t *testing.T) {
	mock := &mockIAMClient{
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			return nil, fmt.Errorf("version not found")
		},
	}
	_, err := FetchManagedPolicy(context.Background(), mock, "arn:aws:iam::aws:policy/X")
	if err == nil {
		t.Fatal("expected error from GetPolicyVersion")
	}
}

func TestFetchRoleBoundary_GetRoleError(t *testing.T) {
	mock := &mockIAMClient{
		getRoleF: func(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return nil, fmt.Errorf("role not found")
		},
	}
	_, err := FetchRoleBoundary(context.Background(), mock, "bad-role")
	if err == nil {
		t.Fatal("expected error from GetRole")
	}
}

func TestFetchRoleBoundary_GetPolicyError(t *testing.T) {
	mock := &mockIAMClient{
		getRoleF: func(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &iamtypes.Role{
					PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
						PermissionsBoundaryArn: aws.String("arn:aws:iam::123456789012:policy/PB"),
					},
				},
			}, nil
		},
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return nil, fmt.Errorf("policy not found")
		},
	}
	_, err := FetchRoleBoundary(context.Background(), mock, "role-with-bad-pb")
	if err == nil {
		t.Fatal("expected error from GetPolicy")
	}
}

func TestFetchRoleBoundary_GetPolicyVersionError(t *testing.T) {
	mock := &mockIAMClient{
		getRoleF: func(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &iamtypes.Role{
					PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
						PermissionsBoundaryArn: aws.String("arn:aws:iam::123456789012:policy/PB"),
					},
				},
			}, nil
		},
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			return nil, fmt.Errorf("version error")
		},
	}
	_, err := FetchRoleBoundary(context.Background(), mock, "role-bad-version")
	if err == nil {
		t.Fatal("expected error from GetPolicyVersion")
	}
}

func TestFetchRolePolicies_ListError(t *testing.T) {
	mock := &mockIAMClient{
		listAttachedRolePoliciesF: func(ctx context.Context, p *iam.ListAttachedRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
	}
	_, err := FetchRolePolicies(context.Background(), mock, "bad-role")
	if err == nil {
		t.Fatal("expected error from ListAttachedRolePolicies")
	}
}

func TestFetchRolePolicies_FetchPolicyError(t *testing.T) {
	mock := &mockIAMClient{
		listAttachedRolePoliciesF: func(ctx context.Context, p *iam.ListAttachedRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []iamtypes.AttachedPolicy{
					{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/Bad"), PolicyName: aws.String("Bad")},
				},
			}, nil
		},
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return nil, fmt.Errorf("cannot get policy")
		},
	}
	_, err := FetchRolePolicies(context.Background(), mock, "role-bad-policy")
	if err == nil {
		t.Fatal("expected error when fetching policy fails")
	}
}
