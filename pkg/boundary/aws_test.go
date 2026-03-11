package boundary

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type mockIAMClient struct {
	getRoleF                  func(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	getPolicyF                func(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	getPolicyVersionF         func(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	listAttachedRolePoliciesF func(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
}

func (m *mockIAMClient) GetRole(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return m.getRoleF(ctx, p, o...)
}

func (m *mockIAMClient) GetPolicy(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return m.getPolicyF(ctx, p, o...)
}

func (m *mockIAMClient) GetPolicyVersion(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return m.getPolicyVersionF(ctx, p, o...)
}

func (m *mockIAMClient) ListAttachedRolePolicies(ctx context.Context, p *iam.ListAttachedRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return m.listAttachedRolePoliciesF(ctx, p, o...)
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

func TestFetchManagedPolicy(t *testing.T) {
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`

	mock := &mockIAMClient{
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			if *p.PolicyArn != "arn:aws:iam::aws:policy/TestPolicy" {
				t.Fatalf("unexpected ARN: %s", *p.PolicyArn)
			}
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			if *p.VersionId != "v1" {
				t.Fatalf("unexpected version: %s", *p.VersionId)
			}
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{
					Document: aws.String(urlEncode(policyDoc)),
				},
			}, nil
		},
	}

	doc, err := FetchManagedPolicy(context.Background(), mock, "arn:aws:iam::aws:policy/TestPolicy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statement))
	}
	if doc.Statement[0].Effect != "Allow" {
		t.Fatalf("expected Allow, got %s", doc.Statement[0].Effect)
	}
}

func TestFetchManagedPolicy_Error(t *testing.T) {
	mock := &mockIAMClient{
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
	}
	_, err := FetchManagedPolicy(context.Background(), mock, "arn:aws:iam::aws:policy/X")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchManagedPolicy_Deny(t *testing.T) {
	pd := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"},{"Effect":"Deny","Action":["s3:DeleteBucket"],"Resource":"*"}]}`
	mock := &mockIAMClient{
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(urlEncode(pd))},
			}, nil
		},
	}
	doc, err := FetchManagedPolicy(context.Background(), mock, "arn:aws:iam::aws:policy/Mix")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statement) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(doc.Statement))
	}
	if doc.Statement[0].Effect != "Allow" {
		t.Fatalf("expected Allow, got %s", doc.Statement[0].Effect)
	}
	if doc.Statement[1].Effect != "Deny" {
		t.Fatalf("expected Deny, got %s", doc.Statement[1].Effect)
	}
}

func TestFetchRolePolicies(t *testing.T) {
	s3D := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`
	ec2D := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeInstances"],"Resource":"*"}]}`
	pDocs := map[string]string{
		"arn:aws:iam::123456789012:policy/S3Policy":  s3D,
		"arn:aws:iam::123456789012:policy/EC2Policy": ec2D,
	}
	mock := &mockIAMClient{
		listAttachedRolePoliciesF: func(ctx context.Context, p *iam.ListAttachedRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []iamtypes.AttachedPolicy{
					{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/S3Policy"), PolicyName: aws.String("S3Policy")},
					{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/EC2Policy"), PolicyName: aws.String("EC2Policy")},
				},
			}, nil
		},
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			d, ok := pDocs[*p.PolicyArn]
			if !ok {
				t.Fatalf("unexpected ARN: %s", *p.PolicyArn)
			}
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(urlEncode(d))},
			}, nil
		},
	}
	result, err := FetchRolePolicies(context.Background(), mock, "test-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(result))
	}
	if _, ok := result["S3Policy"]; !ok {
		t.Fatal("missing S3Policy")
	}
	if _, ok := result["EC2Policy"]; !ok {
		t.Fatal("missing EC2Policy")
	}
}

func TestFetchRolePolicies_Paginated(t *testing.T) {
	d := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`
	calls := 0
	mock := &mockIAMClient{
		listAttachedRolePoliciesF: func(ctx context.Context, p *iam.ListAttachedRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
			calls++
			if calls == 1 {
				return &iam.ListAttachedRolePoliciesOutput{
					AttachedPolicies: []iamtypes.AttachedPolicy{
						{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/P1"), PolicyName: aws.String("P1")},
					},
					IsTruncated: true,
					Marker:      aws.String("next"),
				}, nil
			}
			return &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []iamtypes.AttachedPolicy{
					{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/P2"), PolicyName: aws.String("P2")},
				},
			}, nil
		},
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")},
			}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(urlEncode(d))},
			}, nil
		},
	}
	result, err := FetchRolePolicies(context.Background(), mock, "paged-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if calls != 2 {
		t.Fatalf("expected 2 list calls, got %d", calls)
	}
}

func TestFetchRoleBoundary(t *testing.T) {
	pbDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Resource":"*","NotAction":["s3:GetObject"]}]}`
	mock := &mockIAMClient{
		getRoleF: func(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &iamtypes.Role{
					PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
						PermissionsBoundaryArn: aws.String("arn:aws:iam::123456789012:policy/MyBoundary"),
					},
				},
			}, nil
		},
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{
				Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v3")},
			}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			if *p.VersionId != "v3" {
				t.Fatalf("expected v3, got %s", *p.VersionId)
			}
			return &iam.GetPolicyVersionOutput{
				PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(urlEncode(pbDoc))},
			}, nil
		},
	}
	pb, err := FetchRoleBoundary(context.Background(), mock, "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pb.Policy == nil {
		t.Fatal("expected non-nil policy")
	}
	if len(pb.Policy.Statement) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(pb.Policy.Statement))
	}
	if pb.EvaluationMethod != "Full IAM policy evaluation" {
		t.Fatalf("unexpected method: %s", pb.EvaluationMethod)
	}
}

func TestFetchRoleBoundary_NoBoundary(t *testing.T) {
	mock := &mockIAMClient{
		getRoleF: func(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &iamtypes.Role{},
			}, nil
		},
	}
	_, err := FetchRoleBoundary(context.Background(), mock, "no-pb-role")
	if err == nil {
		t.Fatal("expected error for role without boundary")
	}
}
