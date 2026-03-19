package awsiam

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type mockIAMClient struct {
	getRoleF                  func(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	getRolePolicyF            func(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	getPolicyF                func(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	getPolicyVersionF         func(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	listAttachedRolePoliciesF func(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	listRolePoliciesF         func(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	listRolesF                func(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	listPoliciesF             func(context.Context, *iam.ListPoliciesInput, ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
}

func (m *mockIAMClient) GetRole(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return m.getRoleF(ctx, p, o...)
}

func (m *mockIAMClient) GetRolePolicy(ctx context.Context, p *iam.GetRolePolicyInput, o ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return m.getRolePolicyF(ctx, p, o...)
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

func (m *mockIAMClient) ListRolePolicies(ctx context.Context, p *iam.ListRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return m.listRolePoliciesF(ctx, p, o...)
}

func (m *mockIAMClient) ListRoles(ctx context.Context, p *iam.ListRolesInput, o ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return m.listRolesF(ctx, p, o...)
}

func (m *mockIAMClient) ListPolicies(ctx context.Context, p *iam.ListPoliciesInput, o ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	return m.listPoliciesF(ctx, p, o...)
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

func TestSearchRolesBySubstring(t *testing.T) {
	listCalls := 0
	mock := &mockIAMClient{
		listRolesF: func(ctx context.Context, p *iam.ListRolesInput, o ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
			listCalls++
			if listCalls == 1 {
				return &iam.ListRolesOutput{
					Roles: []iamtypes.Role{
						{RoleName: aws.String("AppReadRole"), Arn: aws.String("arn:aws:iam::123456789012:role/AppReadRole")},
					},
					IsTruncated: true,
					Marker:      aws.String("next"),
				}, nil
			}
			return &iam.ListRolesOutput{
				Roles: []iamtypes.Role{
					{RoleName: aws.String("db-admin"), Arn: aws.String("arn:aws:iam::123456789012:role/db-admin")},
					{RoleName: aws.String("OpsReadOnly"), Arn: aws.String("arn:aws:iam::123456789012:role/OpsReadOnly")},
				},
			}, nil
		},
	}

	roles, err := SearchRolesBySubstring(context.Background(), mock, "read", RoleSearchFilters{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listCalls != 2 {
		t.Fatalf("expected 2 list calls, got %d", listCalls)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 matching roles, got %d", len(roles))
	}
	if roles[0].Name != "AppReadRole" || roles[1].Name != "OpsReadOnly" {
		t.Fatalf("unexpected roles: %+v", roles)
	}
}

func TestSearchRolesBySubstring_LastActivityFilter(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-10 * 24 * time.Hour)
	old := now.Add(-200 * 24 * time.Hour)
	cutoff := now.Add(-90 * 24 * time.Hour)

	mock := &mockIAMClient{
		listRolesF: func(ctx context.Context, p *iam.ListRolesInput, o ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{
				Roles: []iamtypes.Role{
					{
						RoleName:     aws.String("AppFresh"),
						Arn:          aws.String("arn:aws:iam::123456789012:role/AppFresh"),
						RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &recent},
					},
					{
						RoleName:     aws.String("AppOld"),
						Arn:          aws.String("arn:aws:iam::123456789012:role/AppOld"),
						RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &old},
					},
					{RoleName: aws.String("AppNever"), Arn: aws.String("arn:aws:iam::123456789012:role/AppNever")},
				},
			}, nil
		},
	}

	roles, err := SearchRolesBySubstring(context.Background(), mock, "app", RoleSearchFilters{LastActiveAfter: &cutoff})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 matching role after activity filter, got %d", len(roles))
	}
	if roles[0].Name != "AppFresh" {
		t.Fatalf("unexpected role: %+v", roles[0])
	}
	if roles[0].LastUsedAt == nil {
		t.Fatalf("expected last used date in result")
	}
}

func TestSearchManagedPoliciesBySubstring(t *testing.T) {
	mock := &mockIAMClient{
		listPoliciesF: func(ctx context.Context, p *iam.ListPoliciesInput, o ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
			if p.Scope != iamtypes.PolicyScopeTypeLocal {
				t.Fatalf("expected Local scope, got %q", p.Scope)
			}
			return &iam.ListPoliciesOutput{
				Policies: []iamtypes.Policy{
					{PolicyName: aws.String("AppReadPolicy"), Arn: aws.String("arn:aws:iam::123456789012:policy/AppReadPolicy")},
					{PolicyName: aws.String("OpsPolicy"), Arn: aws.String("arn:aws:iam::123456789012:policy/OpsPolicy")},
					{PolicyName: aws.String("DBREAD"), Arn: aws.String("arn:aws:iam::123456789012:policy/DBREAD")},
				},
			}, nil
		},
	}

	policies, err := SearchManagedPoliciesBySubstring(context.Background(), mock, "read", iamtypes.PolicyScopeTypeLocal, PolicySearchFilters{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 matching policies, got %d", len(policies))
	}
	if policies[0].Name != "AppReadPolicy" || policies[1].Name != "DBREAD" {
		t.Fatalf("unexpected policy names: %+v", policies)
	}
}

func TestSearchManagedPoliciesBySubstring_DescriptionFilters(t *testing.T) {
	mock := &mockIAMClient{
		listPoliciesF: func(ctx context.Context, p *iam.ListPoliciesInput, o ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
			return &iam.ListPoliciesOutput{
				Policies: []iamtypes.Policy{
					{
						PolicyName:  aws.String("ReadPolicyA"),
						Arn:         aws.String("arn:aws:iam::123456789012:policy/ReadPolicyA"),
						Description: aws.String("Read-only access for app"),
					},
					{
						PolicyName:  aws.String("ReadPolicyB"),
						Arn:         aws.String("arn:aws:iam::123456789012:policy/ReadPolicyB"),
						Description: aws.String("Read access deprecated"),
					},
					{
						PolicyName: aws.String("ReadPolicyC"),
						Arn:        aws.String("arn:aws:iam::123456789012:policy/ReadPolicyC"),
					},
				},
			}, nil
		},
	}

	policies, err := SearchManagedPoliciesBySubstring(
		context.Background(),
		mock,
		"read",
		iamtypes.PolicyScopeTypeAll,
		PolicySearchFilters{DescriptionContains: "read", DescriptionNotContains: "deprecated"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy after description filters, got %d", len(policies))
	}
	if policies[0].Name != "ReadPolicyA" {
		t.Fatalf("unexpected policy: %+v", policies[0])
	}
}

func TestDescribeRole(t *testing.T) {
	createdAt := time.Now().Add(-24 * time.Hour)
	usedAt := time.Now().Add(-10 * time.Minute)
	inlineDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`

	mock := &mockIAMClient{
		getRoleF: func(ctx context.Context, p *iam.GetRoleInput, o ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{
				RoleName:           aws.String("my-role"),
				Arn:                aws.String("arn:aws:iam::123456789012:role/my-role"),
				CreateDate:         &createdAt,
				MaxSessionDuration: aws.Int32(3600),
				RoleLastUsed:       &iamtypes.RoleLastUsed{LastUsedDate: &usedAt},
			}}, nil
		},
		listAttachedRolePoliciesF: func(ctx context.Context, p *iam.ListAttachedRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{
				{PolicyName: aws.String("ManagedOne"), PolicyArn: aws.String("arn:aws:iam::123456789012:policy/ManagedOne")},
			}}, nil
		},
		listRolePoliciesF: func(ctx context.Context, p *iam.ListRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"InlineOne"}}, nil
		},
		getRolePolicyF: func(ctx context.Context, p *iam.GetRolePolicyInput, o ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
			return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(urlEncode(inlineDoc))}, nil
		},
	}

	role, err := DescribeRole(context.Background(), mock, "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.RoleName != "my-role" {
		t.Fatalf("unexpected role name: %s", role.RoleName)
	}
	if role.SwitchRoleURL == "" {
		t.Fatalf("expected switch role URL")
	}
	if len(role.AttachedPolicies) != 1 || role.AttachedPolicies[0].Name != "ManagedOne" || role.AttachedPolicies[0].ARN != "arn:aws:iam::123456789012:policy/ManagedOne" {
		t.Fatalf("unexpected attached policies: %+v", role.AttachedPolicies)
	}
	if _, ok := role.InlinePolicies["InlineOne"]; !ok {
		t.Fatalf("expected inline policy InlineOne")
	}
}

func TestDescribeManagedPolicy(t *testing.T) {
	createdAt := time.Now().Add(-48 * time.Hour)
	updatedAt := time.Now().Add(-1 * time.Hour)
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}`

	mock := &mockIAMClient{
		getPolicyF: func(ctx context.Context, p *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
				PolicyName:       aws.String("ReadOnly"),
				Arn:              aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"),
				Description:      aws.String("Read only policy"),
				Path:             aws.String("/"),
				DefaultVersionId: aws.String("v1"),
				CreateDate:       &createdAt,
				UpdateDate:       &updatedAt,
			}}, nil
		},
		getPolicyVersionF: func(ctx context.Context, p *iam.GetPolicyVersionInput, o ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(urlEncode(doc))}}, nil
		},
	}

	policyDesc, err := DescribeManagedPolicy(context.Background(), mock, "arn:aws:iam::aws:policy/ReadOnlyAccess")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !policyDesc.IsAWSManaged {
		t.Fatalf("expected AWS managed policy")
	}
	if policyDesc.Name != "ReadOnly" {
		t.Fatalf("unexpected policy name: %s", policyDesc.Name)
	}
	if len(policyDesc.Document.Statement) != 1 {
		t.Fatalf("unexpected parsed policy document")
	}
}
