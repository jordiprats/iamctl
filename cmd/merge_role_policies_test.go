package cmd

import (
	"testing"

	"github.com/jordiprats/iamctl/pkg/policy"
)

func TestMergePolicyDocs_CombinesAllStatements(t *testing.T) {
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
			},
		},
		"PolicyB": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"},
				{Effect: "Deny", Action: "iam:*", Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)

	if merged.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %q", merged.Version)
	}
	if len(merged.Statement) != 3 {
		t.Errorf("expected 3 statements, got %d", len(merged.Statement))
	}
}

func TestMergePolicyDocs_SinglePolicy(t *testing.T) {
	policies := map[string]policy.PolicyDocument{
		"OnlyPolicy": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}, Resource: "arn:aws:s3:::my-bucket/*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)

	if len(merged.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(merged.Statement))
	}
	if merged.Statement[0].Effect != "Allow" {
		t.Errorf("expected Allow, got %q", merged.Statement[0].Effect)
	}
}

func TestMergePolicyDocs_SetsVersionToDefault(t *testing.T) {
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			// Version intentionally empty to simulate missing field
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)

	if merged.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %q", merged.Version)
	}
}

func TestDedupeStatements_RemovesDuplicates(t *testing.T) {
	stmt := policy.Statement{Effect: "Allow", Action: "s3:GetObject", Resource: "*"}
	statements := []policy.Statement{stmt, stmt, stmt}

	deduped := dedupeStatements(statements)

	if len(deduped) != 1 {
		t.Errorf("expected 1 unique statement, got %d", len(deduped))
	}
}

func TestDedupeStatements_KeepsDistinctStatements(t *testing.T) {
	statements := []policy.Statement{
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Allow", Action: "s3:PutObject", Resource: "*"},
		{Effect: "Deny", Action: "iam:*", Resource: "*"},
	}

	deduped := dedupeStatements(statements)

	if len(deduped) != 3 {
		t.Errorf("expected 3 statements, got %d", len(deduped))
	}
}

func TestDedupeStatements_PreservesOrder(t *testing.T) {
	statements := []policy.Statement{
		{Effect: "Allow", Action: "ec2:RunInstances", Resource: "*"},
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Allow", Action: "ec2:RunInstances", Resource: "*"}, // duplicate of first
	}

	deduped := dedupeStatements(statements)

	if len(deduped) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(deduped))
	}
	first, ok := deduped[0].Action.(string)
	if !ok || first != "ec2:RunInstances" {
		t.Errorf("expected first statement to be ec2:RunInstances, got %v", deduped[0].Action)
	}
	second, ok := deduped[1].Action.(string)
	if !ok || second != "s3:GetObject" {
		t.Errorf("expected second statement to be s3:GetObject, got %v", deduped[1].Action)
	}
}

func TestMergeAndDedupeIntegration(t *testing.T) {
	sharedStmt := policy.Statement{Effect: "Allow", Action: "sts:AssumeRole", Resource: "*"}
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version:   "2012-10-17",
			Statement: []policy.Statement{sharedStmt, {Effect: "Allow", Action: "s3:GetObject", Resource: "*"}},
		},
		"PolicyB": {
			Version:   "2012-10-17",
			Statement: []policy.Statement{sharedStmt, {Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"}},
		},
	}

	merged := mergePolicyDocs(policies)
	deduped := policy.PolicyDocument{
		Version:   merged.Version,
		Statement: dedupeStatements(merged.Statement),
	}

	// 4 raw statements merged, but 1 is a duplicate → 3 unique
	if len(deduped.Statement) != 3 {
		t.Errorf("expected 3 unique statements after dedup, got %d", len(deduped.Statement))
	}
}
