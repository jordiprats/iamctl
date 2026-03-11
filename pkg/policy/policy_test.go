package policy

import (
	"testing"
)

func TestExtractActions_AllowAndDeny(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}},
			{Effect: "Deny", Action: []interface{}{"s3:DeleteBucket"}},
		},
	}
	result := ExtractActions(doc)
	if len(result.AllowActions) != 2 {
		t.Fatalf("expected 2 allow, got %d", len(result.AllowActions))
	}
	if len(result.DenyActions) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(result.DenyActions))
	}
	if result.DenyActions[0] != "s3:DeleteBucket" {
		t.Fatalf("unexpected deny: %v", result.DenyActions)
	}
}

func TestExtractActions_NotAction(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Deny", NotAction: []interface{}{"s3:GetObject"}},
		},
	}
	result := ExtractActions(doc)
	if len(result.NotActionStmts) != 1 {
		t.Fatalf("expected 1 NotAction stmt, got %d", len(result.NotActionStmts))
	}
	if result.NotActionStmts[0].Effect != "Deny" {
		t.Fatalf("expected Deny, got %s", result.NotActionStmts[0].Effect)
	}
}

func TestExtractActions_Wildcards(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow", Action: "s3:*"},
		},
	}
	result := ExtractActions(doc)
	if !result.HasWildcards {
		t.Fatal("expected HasWildcards=true")
	}
}

func TestExtractActions_NoWildcards(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow", Action: "s3:GetObject"},
		},
	}
	result := ExtractActions(doc)
	if result.HasWildcards {
		t.Fatal("expected HasWildcards=false")
	}
}

func TestExtractActions_Conditions(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow", Action: "s3:GetObject", Condition: map[string]interface{}{"test": "val"}},
		},
	}
	result := ExtractActions(doc)
	if !result.HasConditions {
		t.Fatal("expected HasConditions=true")
	}
}

func TestExtractActions_NotResource(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow", Action: "s3:GetObject", NotResource: "arn:aws:s3:::secret"},
		},
	}
	result := ExtractActions(doc)
	if !result.HasNotResources {
		t.Fatal("expected HasNotResources=true")
	}
}

func TestExtractActions_EmptyPolicy(t *testing.T) {
	doc := PolicyDocument{}
	result := ExtractActions(doc)
	if len(result.AllowActions) != 0 {
		t.Fatalf("expected 0 allow, got %d", len(result.AllowActions))
	}
	if len(result.DenyActions) != 0 {
		t.Fatalf("expected 0 deny, got %d", len(result.DenyActions))
	}
}

func TestExtractActions_StringAction(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow", Action: "s3:GetObject"},
		},
	}
	result := ExtractActions(doc)
	if len(result.AllowActions) != 1 || result.AllowActions[0] != "s3:GetObject" {
		t.Fatalf("expected [s3:GetObject], got %v", result.AllowActions)
	}
}

func TestExtractActions_NilAction(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow"},
		},
	}
	result := ExtractActions(doc)
	if len(result.AllowActions) != 0 {
		t.Fatal("nil Action should yield 0 actions")
	}
}

func TestExtractActions_Dedup(t *testing.T) {
	doc := PolicyDocument{
		Statement: []Statement{
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:GetObject"}},
		},
	}
	result := ExtractActions(doc)
	if len(result.AllowActions) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(result.AllowActions))
	}
}

func TestWarnings_Wildcards(t *testing.T) {
	e := ExtractedActions{HasWildcards: true}
	w := Warnings(e, true)
	if len(w) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(w))
	}
}

func TestWarnings_All(t *testing.T) {
	e := ExtractedActions{
		HasWildcards:    true,
		HasConditions:   true,
		HasNotResources: true,
		NotActionStmts:  []NotActionStatement{{Effect: "Deny"}},
	}
	w := Warnings(e, false)
	if len(w) != 4 {
		t.Fatalf("expected 4 warnings, got %d", len(w))
	}
}

func TestWarnings_None(t *testing.T) {
	e := ExtractedActions{}
	w := Warnings(e, false)
	if len(w) != 0 {
		t.Fatalf("expected 0 warnings, got %d", len(w))
	}
}

func TestWarnings_PlainVsEmoji(t *testing.T) {
	e := ExtractedActions{HasWildcards: true}
	plain := Warnings(e, true)
	emoji := Warnings(e, false)
	if plain[0][:2] != "!!" {
		t.Fatal("plain text should start with !!")
	}
	// emoji prefix is multi-byte
	if emoji[0][:2] == "!!" {
		t.Fatal("emoji mode should not start with !!")
	}
}

func TestNullableStringSlice_Nil(t *testing.T) {
	result := NullableStringSlice(nil)
	if result == nil {
		t.Fatal("should return non-nil")
	}
	if len(result) != 0 {
		t.Fatalf("expected empty, got %v", result)
	}
}

func TestNullableStringSlice_NonNil(t *testing.T) {
	input := []string{"a", "b"}
	result := NullableStringSlice(input)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}
