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

func TestPatternsCanOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		// Same service wildcards overlap
		{"glue:*", "glue:*A*", true},
		{"glue:*A*", "glue:*", true},
		// Describe* overlaps with D*s (both start with "elasticache:D")
		{"elasticache:Describe*", "elasticache:D*s", true},
		// Different services never overlap
		{"athena:Get*", "glue:*A*", false},
		{"athena:BatchGet*", "elasticache:D*s", false},
		// Specific action shares prefix with wildcard pattern in same service
		{"s3:GetObject", "s3:Get*", true},
		// Same exact token overlaps with itself
		{"ec2:RunInstances", "ec2:RunInstances", true},
		// Star overlaps with anything
		{"*", "s3:GetObject", true},
		{"s3:*", "*", true},
	}
	for _, tc := range tests {
		got := PatternsCanOverlap(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("PatternsCanOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestWildcardOverlapsAnyPattern(t *testing.T) {
	// Wildcard grant overlapping with a NotAction list that has same-service entries
	glueNotAction := []string{"glue:*A*", "glue:*G*", "glue:L*", "glue:S*", "s3:G*"}
	if !WildcardOverlapsAnyPattern("glue:*", glueNotAction) {
		t.Error("glue:* should overlap with glue:*A* and others")
	}

	// Wildcard grant with NO entries for its service → no overlap
	athenaNotAction := []string{"glue:*A*", "s3:G*", "ec2:Des*"}
	if WildcardOverlapsAnyPattern("athena:BatchGet*", athenaNotAction) {
		t.Error("athena:BatchGet* should NOT overlap when no athena entries exist")
	}

	// elasticache:Describe* overlaps with elasticache:D*s (shared prefix "elasticache:D")
	if !WildcardOverlapsAnyPattern("elasticache:Describe*", []string{"elasticache:D*s"}) {
		t.Error("elasticache:Describe* should detect overlap with elasticache:D*s")
	}
}

func TestPatternsCanOverlap_ServiceBoundary(t *testing.T) {
	// Two services that share a common prefix string should NOT overlap
	// "ec2:" vs "ec2-instance-connect:" — different services despite shared start
	// fixedPrefix("ec2:*") = "ec2:" (4 chars)
	// fixedPrefix("ec2-instance-connect:*") = "ec2-instance-connect:" (21 chars)
	// min=4: "ec2:" vs "ec2-" — '2' vs '2', ':' vs '-' → NOT equal
	if PatternsCanOverlap("ec2:*", "ec2-instance-connect:*") {
		t.Error("ec2:* and ec2-instance-connect:* should NOT overlap — they are different services")
	}

	// Sanity: same service always overlaps
	if !PatternsCanOverlap("ec2:*", "ec2:Describe*") {
		t.Error("ec2:* and ec2:Describe* should overlap")
	}
}

func TestPatternsCanOverlap_EmptyPatterns(t *testing.T) {
	// Both empty → overlap at zero length
	if !PatternsCanOverlap("", "") {
		t.Error("two empty patterns should be considered overlapping")
	}
	// One empty → min=0 → the zero-length prefix matches anything
	if !PatternsCanOverlap("", "s3:GetObject") {
		t.Error("empty pattern should overlap with anything")
	}
}

func TestPatternsCanOverlap_CaseInsensitive(t *testing.T) {
	// Prefix comparison is case-insensitive
	if !PatternsCanOverlap("S3:G*", "s3:GetObject") {
		t.Error("prefix comparison should be case-insensitive")
	}
}

func TestWildcardOverlapsAnyPattern_RealisticNotActionList(t *testing.T) {
	// Simulate a realistic minified-PB NotAction list (subset of the user's real case)
	notAction := []string{
		"ec2:Describe*", "ec2:CreateTags",
		"glue:*A*", "glue:*G*", "glue:L*", "glue:S*",
		"elasticache:D*s", "elasticache:L*",
		"s3:G*", "s3:List*", "s3:*J*",
		"iam:Get*", "iam:List*",
	}

	// Services WITH entries: should overlap — their fixed prefix matches at least one NotAction entry
	withOverlap := []string{"ec2:*", "glue:*", "elasticache:Describe*", "s3:*", "s3:Describe*", "iam:*"}
	for _, action := range withOverlap {
		if !WildcardOverlapsAnyPattern(action, notAction) {
			t.Errorf("expected %q to overlap with at least one NotAction entry", action)
		}
	}

	// Services WITHOUT entries: should NOT overlap
	// Note: iam:Create* does NOT overlap with iam:Get*/iam:List* because its fixed prefix
	// "iam:Create" diverges from "iam:Get" and "iam:List" at the 5th character.
	// It will therefore be correctly reported as "blocked" (all creates are outside the boundary).
	noOverlap := []string{"athena:*", "athena:Get*", "athena:BatchGet*", "cloudtrail:*", "cloudtrail:DescribeTrails", "iam:Create*"}
	for _, action := range noOverlap {
		if WildcardOverlapsAnyPattern(action, notAction) {
			t.Errorf("expected %q to NOT overlap with any NotAction entry", action)
		}
	}
}
