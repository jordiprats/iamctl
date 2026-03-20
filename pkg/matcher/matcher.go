package matcher

import (
	"regexp"
	"strings"
)

// ExtractStrings normalises an Action/NotAction value (string or []interface{}) into a string slice.
func ExtractStrings(value interface{}) []string {
	var result []string
	switch v := value.(type) {
	case string:
		result = append(result, v)
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}
	return result
}

// IamPatternToRegex converts an IAM action pattern (with * and ?) into a compiled regex.
func IamPatternToRegex(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

// MatchesAnyPattern returns true if the action matches any of the given IAM patterns.
func MatchesAnyPattern(action string, patterns []string) (bool, []string) {
	var matches []string
	for _, pattern := range patterns {
		re, err := IamPatternToRegex(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(action) {
			matches = append(matches, pattern)
		}
	}
	return len(matches) > 0, matches
}

// IsWildcardAction returns true if the action string contains * or ?.
func IsWildcardAction(action string) bool {
	return strings.ContainsAny(action, "*?")
}

// fixedPrefix returns the portion of an IAM pattern before the first wildcard character.
func fixedPrefix(pattern string) string {
	for i, ch := range pattern {
		if ch == '*' || ch == '?' {
			return pattern[:i]
		}
	}
	return pattern
}

// PatternsCanOverlap reports whether two IAM glob patterns can possibly match some
// common action string. It uses a prefix-based heuristic: if the fixed prefix of one
// pattern is a prefix of the fixed prefix of the other (case-insensitively), the
// patterns can overlap. This is a necessary (not sufficient) condition, but it is
// accurate for the IAM "service:Action" namespace.
func PatternsCanOverlap(a, b string) bool {
	pa := fixedPrefix(a)
	pb := fixedPrefix(b)
	la, lb := len(pa), len(pb)
	minLen := la
	if lb < minLen {
		minLen = lb
	}
	return strings.EqualFold(pa[:minLen], pb[:minLen])
}

// WildcardOverlapsAnyPattern reports whether the wildcard action pattern overlaps
// with at least one of the given patterns, i.e. there exists some specific IAM action
// that would match both. This is used to detect partial NotAction coverage for wildcard
// grant tokens and avoid false-positive "blocked" results.
func WildcardOverlapsAnyPattern(action string, patterns []string) bool {
	for _, p := range patterns {
		if PatternsCanOverlap(action, p) {
			return true
		}
	}
	return false
}
