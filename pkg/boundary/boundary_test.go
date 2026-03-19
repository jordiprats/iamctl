package boundary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jordiprats/iamctl/pkg/policy"
)

func TestEvaluatePolicy_AllowAll(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("Allow * should allow any action")
	}
}

func TestEvaluatePolicy_AllowSpecific(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("should allow s3:GetObject")
	}
	if EvaluatePolicy("ec2:RunInstances", doc) {
		t.Fatal("should not allow ec2:RunInstances")
	}
}

func TestEvaluatePolicy_DenyOverridesAllow(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", Action: []interface{}{"iam:CreateRole"}},
		},
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("explicit Deny should override Allow *")
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("non-denied action should still be allowed")
	}
}

func TestEvaluatePolicy_DenyWildcard(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", Action: "iam:*"},
		},
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("iam:* deny should block iam:CreateRole")
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("s3:GetObject should still be allowed")
	}
}

func TestEvaluatePolicy_NotActionAllow(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", NotAction: []interface{}{"iam:*"}},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("NotAction iam:* with Allow should allow s3:GetObject")
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("NotAction iam:* with Allow should NOT allow iam:CreateRole")
	}
}

func TestEvaluatePolicy_NotActionDeny(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", NotAction: []interface{}{"s3:GetObject"}},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("Deny NotAction [s3:GetObject] should NOT deny s3:GetObject")
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("Deny NotAction [s3:GetObject] should deny iam:CreateRole")
	}
}

func TestEvaluatePolicy_NoStatements(t *testing.T) {
	doc := policy.PolicyDocument{}
	if EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("empty policy should deny everything")
	}
}

func TestEvaluatePolicy_CaseInsensitive(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "S3:GetObject"},
		},
	}
	if !EvaluatePolicy("s3:getobject", doc) {
		t.Fatal("matching should be case-insensitive")
	}
}

func TestIsActionAllowed_WithPolicy(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:*"}},
			},
		},
	}
	if !IsActionAllowed("s3:GetObject", pb) {
		t.Fatal("should allow s3:GetObject")
	}
	if IsActionAllowed("iam:CreateRole", pb) {
		t.Fatal("should not allow iam:CreateRole")
	}
}

func TestIsActionAllowed_WithPatterns(t *testing.T) {
	pb := &PermissionBoundary{
		Patterns: []string{"s3:*", "ec2:Describe*"},
	}
	if !IsActionAllowed("s3:GetObject", pb) {
		t.Fatal("should allow via pattern")
	}
	if !IsActionAllowed("ec2:DescribeInstances", pb) {
		t.Fatal("should allow via pattern")
	}
	if IsActionAllowed("iam:CreateRole", pb) {
		t.Fatal("should not allow iam:CreateRole")
	}
}

func TestDiffPolicies(t *testing.T) {
	pbA := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:*", "ec2:*"}},
			},
		},
	}
	pbB := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:*", "iam:*"}},
			},
		},
	}
	actions := []string{"s3:GetObject", "ec2:RunInstances", "iam:CreateRole"}
	onlyA, onlyB := DiffPolicies(pbA, pbB, actions)
	if len(onlyA) != 1 || onlyA[0] != "ec2:RunInstances" {
		t.Fatalf("expected onlyA=[ec2:RunInstances], got %v", onlyA)
	}
	if len(onlyB) != 1 || onlyB[0] != "iam:CreateRole" {
		t.Fatalf("expected onlyB=[iam:CreateRole], got %v", onlyB)
	}
}

func TestDiffPolicies_Identical(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "*"},
			},
		},
	}
	onlyA, onlyB := DiffPolicies(pb, pb, []string{"s3:GetObject"})
	if len(onlyA) != 0 || len(onlyB) != 0 {
		t.Fatalf("identical PBs should have no diff, got A=%v B=%v", onlyA, onlyB)
	}
}

func TestLoadFromFile_PolicyVersionWrapper(t *testing.T) {
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-pb.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pb.Policy == nil {
		t.Fatal("expected policy-based PB")
	}
	if pb.EvaluationMethod != "Full IAM policy evaluation" {
		t.Fatalf("unexpected method: %s", pb.EvaluationMethod)
	}
}

func TestLoadFromFile_DirectPolicy(t *testing.T) {
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-policy.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pb.Policy == nil {
		t.Fatal("expected policy-based PB")
	}
}

func TestLoadFromFile_JsonPatterns(t *testing.T) {
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "patterns.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pb.Patterns) == 0 {
		t.Fatal("expected pattern-based PB")
	}
	if pb.EvaluationMethod != "Simple pattern matching" {
		t.Fatalf("unexpected method: %s", pb.EvaluationMethod)
	}
}

func TestLoadFromFile_TextFile(t *testing.T) {
	// Create a temp text file with patterns
	tmp, err := os.CreateTemp("", "pb-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("s3:GetObject\n# comment\nec2:*\n")
	tmp.Close()

	pb, err := LoadFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pb.Patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d: %v", len(pb.Patterns), pb.Patterns)
	}
}

func TestLoadFromFile_Nonexistent(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
