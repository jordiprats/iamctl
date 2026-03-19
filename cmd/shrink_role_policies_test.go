package cmd

import (
	"testing"

	"github.com/jordiprats/iamctl/pkg/policy"
)

func TestShrinkDocument_RemovesUnusedActions(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Effect:   "Allow",
				Action:   []interface{}{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"},
				Resource: "*",
			},
		},
	}
	accessed := map[string]bool{
		"s3:getobject": true,
		"s3:putobject": true,
	}

	shrunk, removed := shrinkDocument(doc, accessed)

	if len(removed) != 1 {
		t.Fatalf("expected 1 removed action, got %d: %v", len(removed), removed)
	}
	if removed[0] != "s3:DeleteObject" {
		t.Errorf("expected s3:DeleteObject removed, got %s", removed[0])
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_PreservesDenyStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Effect:   "Deny",
				Action:   []interface{}{"iam:*"},
				Resource: "*",
			},
		},
	}
	accessed := map[string]bool{}

	shrunk, removed := shrinkDocument(doc, accessed)

	if len(removed) != 0 {
		t.Fatalf("Deny statements should not be pruned, got %d removed", len(removed))
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement preserved, got %d", len(shrunk.Statement))
	}
	if shrunk.Statement[0].Effect != "Deny" {
		t.Errorf("expected Deny, got %s", shrunk.Statement[0].Effect)
	}
}

func TestShrinkDocument_PreservesNotActionStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Effect:    "Allow",
				NotAction: []interface{}{"iam:*"},
				Resource:  "*",
			},
		},
	}
	accessed := map[string]bool{}

	shrunk, removed := shrinkDocument(doc, accessed)

	if len(removed) != 0 {
		t.Fatalf("NotAction statements should not be pruned, got %d removed", len(removed))
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement preserved, got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_RemovesEntireStatementIfAllUnused(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Effect:   "Allow",
				Action:   []interface{}{"s3:GetObject"},
				Resource: "*",
			},
		},
	}
	accessed := map[string]bool{}

	shrunk, removed := shrinkDocument(doc, accessed)

	if len(removed) != 1 {
		t.Fatalf("expected 1 removed action, got %d", len(removed))
	}
	if len(shrunk.Statement) != 0 {
		t.Fatalf("expected 0 statements (entire statement pruned), got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_SingleSurvivingActionBecomesString(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Effect:   "Allow",
				Action:   []interface{}{"s3:GetObject", "s3:PutObject"},
				Resource: "*",
			},
		},
	}
	accessed := map[string]bool{
		"s3:getobject": true,
	}

	shrunk, removed := shrinkDocument(doc, accessed)

	if len(removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(removed))
	}
	action, ok := shrunk.Statement[0].Action.(string)
	if !ok {
		t.Fatalf("expected string action for single surviving, got %T", shrunk.Statement[0].Action)
	}
	if action != "s3:GetObject" {
		t.Errorf("expected s3:GetObject, got %s", action)
	}
}

func TestShrinkDocument_PreservesStatementsWithNilAction(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Effect:   "Allow",
				Resource: "*",
			},
		},
	}
	accessed := map[string]bool{}

	shrunk, _ := shrinkDocument(doc, accessed)

	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement preserved (nil Action), got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_PreservesSidAndCondition(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Sid:       "AllowS3",
				Effect:    "Allow",
				Action:    []interface{}{"s3:GetObject", "s3:PutObject"},
				Resource:  "arn:aws:s3:::my-bucket/*",
				Condition: map[string]interface{}{"StringEquals": map[string]interface{}{"s3:prefix": "home/"}},
			},
		},
	}
	accessed := map[string]bool{
		"s3:getobject": true,
	}

	shrunk, _ := shrinkDocument(doc, accessed)

	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(shrunk.Statement))
	}
	if shrunk.Statement[0].Sid != "AllowS3" {
		t.Errorf("Sid not preserved: got %q", shrunk.Statement[0].Sid)
	}
	if shrunk.Statement[0].Condition == nil {
		t.Error("Condition not preserved")
	}
	if shrunk.Statement[0].Resource != "arn:aws:s3:::my-bucket/*" {
		t.Errorf("Resource not preserved: got %v", shrunk.Statement[0].Resource)
	}
}

func TestShrinkDocument_MixedStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}, Resource: "*"},
			{Effect: "Deny", Action: []interface{}{"iam:*"}, Resource: "*"},
			{Effect: "Allow", Action: []interface{}{"ec2:RunInstances"}, Resource: "*"},
			{Effect: "Allow", NotAction: []interface{}{"sts:*"}, Resource: "*"},
		},
	}
	accessed := map[string]bool{
		"s3:getobject": true,
	}

	shrunk, removed := shrinkDocument(doc, accessed)

	if len(removed) != 2 {
		t.Fatalf("expected 2 removed, got %d: %v", len(removed), removed)
	}
	// Deny + NotAction + surviving Allow = 3 statements
	if len(shrunk.Statement) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_StringAction(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		},
	}
	accessed := map[string]bool{
		"s3:getobject": true,
	}

	shrunk, removed := shrinkDocument(doc, accessed)

	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(shrunk.Statement))
	}
}

func TestIsActionAccessed_DirectMatch(t *testing.T) {
	accessed := map[string]bool{
		"s3:getobject": true,
	}
	if !isActionAccessed("s3:GetObject", accessed) {
		t.Error("expected case-insensitive match for s3:GetObject")
	}
}

func TestIsActionAccessed_NoMatch(t *testing.T) {
	accessed := map[string]bool{
		"s3:getobject": true,
	}
	if isActionAccessed("s3:PutObject", accessed) {
		t.Error("s3:PutObject should not match")
	}
}

func TestIsActionAccessed_WildcardMatch(t *testing.T) {
	accessed := map[string]bool{
		"s3:getobject": true,
		"s3:putobject": true,
	}
	if !isActionAccessed("s3:*", accessed) {
		t.Error("s3:* should match accessed s3 actions")
	}
}

func TestIsActionAccessed_WildcardNoMatch(t *testing.T) {
	accessed := map[string]bool{
		"ec2:describeinstances": true,
	}
	if isActionAccessed("s3:*", accessed) {
		t.Error("s3:* should not match ec2 actions")
	}
}

func TestIsActionAccessed_PartialWildcard(t *testing.T) {
	accessed := map[string]bool{
		"s3:getobject":       true,
		"s3:getbucketpolicy": true,
	}
	if !isActionAccessed("s3:Get*", accessed) {
		t.Error("s3:Get* should match s3:getobject")
	}
}

func TestIsActionAccessed_EmptyAccessed(t *testing.T) {
	accessed := map[string]bool{}
	if isActionAccessed("s3:GetObject", accessed) {
		t.Error("nothing accessed, should return false")
	}
	if isActionAccessed("s3:*", accessed) {
		t.Error("wildcard with nothing accessed should return false")
	}
}

func TestMergePolicyDocs(t *testing.T) {
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
				{Effect: "Allow", Action: "ec2:RunInstances", Resource: "*"},
				{Effect: "Deny", Action: "iam:*", Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)

	if merged.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", merged.Version)
	}
	if len(merged.Statement) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(merged.Statement))
	}
}

func TestMergePolicyDocs_Empty(t *testing.T) {
	policies := map[string]policy.PolicyDocument{}

	merged := mergePolicyDocs(policies)

	if len(merged.Statement) != 0 {
		t.Fatalf("expected 0 statements for empty input, got %d", len(merged.Statement))
	}
}
