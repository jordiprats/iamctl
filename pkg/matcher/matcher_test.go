package matcher

import (
	"testing"
)

func TestExtractStrings_String(t *testing.T) {
	result := ExtractStrings("s3:GetObject")
	if len(result) != 1 || result[0] != "s3:GetObject" {
		t.Fatalf("expected [s3:GetObject], got %v", result)
	}
}

func TestExtractStrings_Slice(t *testing.T) {
	input := []interface{}{"s3:GetObject", "s3:PutObject"}
	result := ExtractStrings(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result))
	}
	if result[0] != "s3:GetObject" || result[1] != "s3:PutObject" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestExtractStrings_Nil(t *testing.T) {
	result := ExtractStrings(nil)
	if len(result) != 0 {
		t.Fatalf("expected empty, got %v", result)
	}
}

func TestExtractStrings_NonStringInSlice(t *testing.T) {
	input := []interface{}{"s3:GetObject", 42, "ec2:Run"}
	result := ExtractStrings(input)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d: %v", len(result), result)
	}
}

func TestIamPatternToRegex_Exact(t *testing.T) {
	re, err := IamPatternToRegex("s3:GetObject")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("s3:GetObject") {
		t.Fatal("should match exact")
	}
	if !re.MatchString("S3:GETOBJECT") {
		t.Fatal("should match case-insensitive")
	}
	if re.MatchString("s3:GetObjectAcl") {
		t.Fatal("should not match longer string")
	}
}

func TestIamPatternToRegex_Star(t *testing.T) {
	re, err := IamPatternToRegex("s3:*")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("s3:GetObject") {
		t.Fatal("s3:* should match s3:GetObject")
	}
	if !re.MatchString("s3:PutObject") {
		t.Fatal("s3:* should match s3:PutObject")
	}
	if re.MatchString("ec2:DescribeInstances") {
		t.Fatal("s3:* should not match ec2:*")
	}
}

func TestIamPatternToRegex_Question(t *testing.T) {
	re, err := IamPatternToRegex("s3:Get?bject")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("s3:GetObject") {
		t.Fatal("should match with ? wildcard")
	}
	if re.MatchString("s3:GetXXbject") {
		t.Fatal("? should match exactly one char")
	}
}

func TestIamPatternToRegex_DoubleWildcard(t *testing.T) {
	re, err := IamPatternToRegex("*")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("anything:Here") {
		t.Fatal("* should match everything")
	}
}

func TestMatchesAnyPattern(t *testing.T) {
	patterns := []string{"s3:Get*", "ec2:Describe*"}
	matched, matches := MatchesAnyPattern("s3:GetObject", patterns)
	if !matched {
		t.Fatal("should match s3:Get*")
	}
	if len(matches) != 1 || matches[0] != "s3:Get*" {
		t.Fatalf("unexpected matches: %v", matches)
	}
}

func TestMatchesAnyPattern_CaseInsensitive(t *testing.T) {
	patterns := []string{"S3:GetObject"}
	matched, _ := MatchesAnyPattern("s3:getobject", patterns)
	if !matched {
		t.Fatal("should match case-insensitive")
	}
}

func TestMatchesAnyPattern_NoMatch(t *testing.T) {
	patterns := []string{"s3:Get*", "ec2:Describe*"}
	matched, _ := MatchesAnyPattern("iam:CreateRole", patterns)
	if matched {
		t.Fatal("should not match")
	}
}

func TestMatchesAnyPattern_MultipleMatches(t *testing.T) {
	patterns := []string{"s3:*", "s3:Get*"}
	matched, matches := MatchesAnyPattern("s3:GetObject", patterns)
	if !matched {
		t.Fatal("should match")
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

func TestMatchesAnyPattern_Empty(t *testing.T) {
	matched, _ := MatchesAnyPattern("s3:GetObject", nil)
	if matched {
		t.Fatal("empty patterns should not match")
	}
}

func TestIsWildcardAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"s3:GetObject", false},
		{"s3:*", true},
		{"ec2:Describe*", true},
		{"s3:Get?bject", true},
		{"*", true},
		{"iam:CreateRole", false},
	}
	for _, tc := range tests {
		got := IsWildcardAction(tc.action)
		if got != tc.want {
			t.Errorf("IsWildcardAction(%q) = %v, want %v", tc.action, got, tc.want)
		}
	}
}
