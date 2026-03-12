package cfn

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestParseTemplate(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "test-cf-template.yaml")
	tmpl, err := ParseTemplate(path)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if len(tmpl.Resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(tmpl.Resources))
	}
}

func TestExtractIAMRoles(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "test-cf-template.yaml")
	tmpl, err := ParseTemplate(path)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	roles, err := ExtractIAMRoles(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 IAM roles, got %d", len(roles))
	}
	sort.Slice(roles, func(i, j int) bool {
		return roles[i].LogicalID < roles[j].LogicalID
	})

	another := roles[0]
	if another.LogicalID != "AnotherRole" {
		t.Errorf("expected AnotherRole, got %s", another.LogicalID)
	}
	if another.Properties.PermissionBoundary != "arn:aws:iam::123456789012:policy/MyBoundary" {
		t.Errorf("unexpected PB: %s", another.Properties.PermissionBoundary)
	}

	lambda := roles[1]
	if lambda.LogicalID != "LambdaRole" {
		t.Errorf("expected LambdaRole, got %s", lambda.LogicalID)
	}
	if len(lambda.Properties.ManagedPolicyArns) != 2 {
		t.Errorf("expected 2 managed ARNs, got %d", len(lambda.Properties.ManagedPolicyArns))
	}
	if len(lambda.Properties.InlinePolicies) != 1 {
		t.Errorf("expected 1 inline policy, got %d", len(lambda.Properties.InlinePolicies))
	}
	inlineDoc, ok := lambda.Properties.InlinePolicies["InlineAccess"]
	if !ok {
		t.Fatal("inline policy InlineAccess not found")
	}
	if len(inlineDoc.Statement) != 2 {
		t.Errorf("expected 2 statements, got %d", len(inlineDoc.Statement))
	}
}

func TestExtractIAMRoles_IntrinsicFunctions(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "test-cf-intrinsics.yaml")
	tmpl, err := ParseTemplate(path)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	roles, err := ExtractIAMRoles(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMRoles: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 IAM role, got %d", len(roles))
	}
	role := roles[0]
	if len(role.Properties.ManagedPolicyArns) != 1 {
		t.Errorf("expected 1 ARN, got %d", len(role.Properties.ManagedPolicyArns))
	}
	if role.Properties.PermissionBoundary != "" {
		t.Errorf("expected empty PB, got %q", role.Properties.PermissionBoundary)
	}
	if len(role.Properties.InlinePolicies) != 1 {
		t.Errorf("expected 1 inline policy, got %d", len(role.Properties.InlinePolicies))
	}
}

func TestParseTemplate_FileNotFound(t *testing.T) {
	_, err := ParseTemplate("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseTemplate_InvalidYAML(t *testing.T) {
	tmp, err := os.CreateTemp("", "bad-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString("{{{{bad")
	tmp.Close()
	_, err = ParseTemplate(tmp.Name())
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestExtractIAMPolicies(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "test-cf-policies.yaml")
	tmpl, err := ParseTemplate(path)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	policies, err := ExtractIAMPolicies(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMPolicies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 IAM policies, got %d", len(policies))
	}
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].LogicalID < policies[j].LogicalID
	})

	inline := policies[0]
	if inline.LogicalID != "MyInlinePolicy" {
		t.Errorf("expected MyInlinePolicy, got %s", inline.LogicalID)
	}
	if inline.Type != "AWS::IAM::Policy" {
		t.Errorf("expected AWS::IAM::Policy, got %s", inline.Type)
	}
	if len(inline.PolicyDocument.Statement) != 1 {
		t.Errorf("expected 1 statement, got %d", len(inline.PolicyDocument.Statement))
	}

	managed := policies[1]
	if managed.LogicalID != "MyManagedPolicy" {
		t.Errorf("expected MyManagedPolicy, got %s", managed.LogicalID)
	}
	if managed.Type != "AWS::IAM::ManagedPolicy" {
		t.Errorf("expected AWS::IAM::ManagedPolicy, got %s", managed.Type)
	}
	if len(managed.PolicyDocument.Statement) != 2 {
		t.Errorf("expected 2 statements, got %d", len(managed.PolicyDocument.Statement))
	}
}

func TestExtractIAMPolicies_NoMatch(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "test-cf-template.yaml")
	tmpl, err := ParseTemplate(path)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	policies, err := ExtractIAMPolicies(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMPolicies: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected 0 policies from role-only template, got %d", len(policies))
	}
}
