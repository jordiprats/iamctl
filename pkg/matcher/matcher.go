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
