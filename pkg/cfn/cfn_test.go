package cfn

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		t.Errorf("expected 1 resolved ARN, got %d", len(role.Properties.ManagedPolicyArns))
	}
	if len(role.Properties.ManagedPolicyArnsRaw) != 2 {
		t.Errorf("expected 2 unresolved ARNs (Fn::Join + !Sub), got %d", len(role.Properties.ManagedPolicyArnsRaw))
	}
	if role.Properties.PermissionBoundary != "" {
		t.Errorf("expected empty PB string, got %q", role.Properties.PermissionBoundary)
	}
	if role.Properties.PermissionBoundaryRaw == nil {
		t.Error("expected PermissionBoundaryRaw to be non-nil")
	}
	if len(role.Properties.InlinePolicies) != 1 {
		t.Errorf("expected 1 inline policy, got %d", len(role.Properties.InlinePolicies))
	}

	// Resolve the intrinsic PB with test variables
	vars := map[string]string{"AWS::AccountId": "123456789012"}
	resolved, err := ResolveIntrinsic(role.Properties.PermissionBoundaryRaw, vars)
	if err != nil {
		t.Fatalf("ResolveIntrinsic PB: %v", err)
	}
	if resolved != "arn:aws:iam::123456789012:policy/MyBoundary" {
		t.Errorf("unexpected resolved PB: %s", resolved)
	}

	// Resolve the intrinsic ManagedPolicyArn
	resolvedArn, err := ResolveIntrinsic(role.Properties.ManagedPolicyArnsRaw[0], vars)
	if err != nil {
		t.Fatalf("ResolveIntrinsic ARN: %v", err)
	}
	if resolvedArn != "arn:aws:iam::123456789012:policy/CustomPolicy" {
		t.Errorf("unexpected resolved ARN: %s", resolvedArn)
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

func TestResolveIntrinsic_FnJoin(t *testing.T) {
	vars := map[string]string{"AWS::AccountId": "111222333444", "AWS::Region": "us-west-2"}
	value := map[string]interface{}{
		"Fn::Join": []interface{}{
			"",
			[]interface{}{
				"arn:aws:iam::",
				map[string]interface{}{"Ref": "AWS::AccountId"},
				":policy/MyBoundary",
			},
		},
	}
	result, err := ResolveIntrinsic(value, vars)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "arn:aws:iam::111222333444:policy/MyBoundary" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestResolveIntrinsic_FnSub(t *testing.T) {
	vars := map[string]string{"AWS::AccountId": "111222333444"}
	value := map[string]interface{}{
		"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:policy/MyBoundary",
	}
	result, err := ResolveIntrinsic(value, vars)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "arn:aws:iam::111222333444:policy/MyBoundary" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestResolveIntrinsic_Ref(t *testing.T) {
	vars := map[string]string{"AWS::AccountId": "111222333444"}
	value := map[string]interface{}{"Ref": "AWS::AccountId"}
	result, err := ResolveIntrinsic(value, vars)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "111222333444" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestResolveIntrinsic_String(t *testing.T) {
	result, err := ResolveIntrinsic("plain-string", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "plain-string" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestResolveIntrinsic_UnresolvedRef(t *testing.T) {
	value := map[string]interface{}{"Ref": "SomeParameter"}
	_, err := ResolveIntrinsic(value, map[string]string{})
	if err == nil {
		t.Fatal("expected error for unresolved Ref")
	}
}

func TestExtractIAMRoles_SubStringARN(t *testing.T) {
	// Verify that a !Sub-style string ARN (containing ${...}) ends up in ManagedPolicyArnsRaw
	// and resolves correctly, not passed literally to AWS.
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
		t.Fatalf("expected 1 role, got %d", len(roles))
	}
	role := roles[0]

	// The !Sub ARN must NOT appear in ManagedPolicyArns (plain strings)
	for _, arn := range role.Properties.ManagedPolicyArns {
		if strings.Contains(arn, "${") {
			t.Errorf("unresolved ${...} placeholder leaked into ManagedPolicyArns: %s", arn)
		}
	}

	// It must be in ManagedPolicyArnsRaw as a Fn::Sub wrapper
	var subEntry map[string]interface{}
	for _, raw := range role.Properties.ManagedPolicyArnsRaw {
		if m, ok := raw.(map[string]interface{}); ok {
			if _, hasSub := m["Fn::Sub"]; hasSub {
				subEntry = m
				break
			}
		}
	}
	if subEntry == nil {
		t.Fatal("expected a Fn::Sub entry in ManagedPolicyArnsRaw for the !Sub ARN")
	}

	// Verify it resolves correctly with pseudo-params
	vars := map[string]string{
		"AWS::AccountId": "123456789012",
		"AWS::Region":    "eu-west-1",
	}
	resolved, err := ResolveIntrinsic(subEntry, vars)
	if err != nil {
		t.Fatalf("ResolveIntrinsic Fn::Sub ARN: %v", err)
	}
	if resolved != "arn:aws:iam::123456789012:policy/SubPolicy-eu-west-1" {
		t.Errorf("unexpected resolved ARN: %s", resolved)
	}
}
