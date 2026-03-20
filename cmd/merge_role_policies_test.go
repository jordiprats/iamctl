package cmd

import (
	"testing"

	"github.com/jordiprats/iamctl/pkg/policy"
)

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

func TestFilterDenyStatements_RemovesDenyByEffect(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Deny", Action: "iam:*", Resource: "*"},
		{Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"},
		{Effect: "deny", Action: "s3:DeleteObject", Resource: "*"}, // lowercase
	}

	kept := filterDenyStatements(stmts)

	if len(kept) != 2 {
		t.Errorf("expected 2 Allow statements, got %d", len(kept))
	}
	for _, stmt := range kept {
		if stmt.Effect == "Deny" || stmt.Effect == "deny" {
			t.Errorf("Deny statement not removed: %+v", stmt)
		}
	}
}

func TestFilterDenyStatements_NoDenyStatements(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"},
	}

	kept := filterDenyStatements(stmts)

	if len(kept) != 2 {
		t.Errorf("expected all 2 statements preserved, got %d", len(kept))
	}
}

func TestFilterDenyStatements_AllDeny(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "Deny", Action: "iam:*", Resource: "*"},
		{Effect: "Deny", Action: "s3:*", Resource: "*"},
	}

	kept := filterDenyStatements(stmts)

	if len(kept) != 0 {
		t.Errorf("expected 0 statements remaining, got %d", len(kept))
	}
}

func TestStrict_CompactsEquivalentStatements(t *testing.T) {
	// Two policies each have the same statement but with different Sids.
	// compactStatements should deduplicate them (by key-without-Sid) and clear the Sid.
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Sid: "SidA", Effect: "Allow", Action: []interface{}{"s3:GetObject"}, Resource: "*"},
			},
		},
		"PolicyB": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Sid: "SidB", Effect: "Allow", Action: []interface{}{"s3:GetObject"}, Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)
	compacted := compactStatements(merged.Statement)

	// Both statements are identical (ignoring Sid) → should collapse to 1 with Sid cleared
	if len(compacted) != 1 {
		t.Fatalf("expected 1 compacted statement, got %d", len(compacted))
	}
	if compacted[0].Sid != "" {
		t.Errorf("expected Sid cleared on duplicate, got %q", compacted[0].Sid)
	}
}

func TestStrict_NormalizesUnsortedActions(t *testing.T) {
	// compactStatements normalizes action lists: sorts and deduplicates within each statement
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:PutObject", "s3:GetObject", "s3:GetObject"}, Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)
	compacted := compactStatements(merged.Statement)

	if len(compacted) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(compacted))
	}
	actions, ok := compacted[0].Action.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{} action, got %T", compacted[0].Action)
	}
	if len(actions) != 2 {
		t.Errorf("expected 2 unique actions after normalize, got %d: %v", len(actions), actions)
	}
	// Should be sorted
	if actions[0].(string) != "s3:GetObject" || actions[1].(string) != "s3:PutObject" {
		t.Errorf("expected sorted actions [s3:GetObject, s3:PutObject], got %v", actions)
	}
}
