package policy

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iam-pb-check/pkg/matcher"
)

// PolicyDocument represents an IAM policy document.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents a single IAM policy statement.
type Statement struct {
	Sid          string      `json:"Sid,omitempty"`
	Effect       string      `json:"Effect"`
	Action       interface{} `json:"Action,omitempty"`
	NotAction    interface{} `json:"NotAction,omitempty"`
	Resource     interface{} `json:"Resource,omitempty"`
	NotResource  interface{} `json:"NotResource,omitempty"`
	Principal    interface{} `json:"Principal,omitempty"`
	NotPrincipal interface{} `json:"NotPrincipal,omitempty"`
	Condition    interface{} `json:"Condition,omitempty"`
}

// PolicyVersionWrapper wraps the AWS IAM GetPolicyVersion response.
type PolicyVersionWrapper struct {
	PolicyVersion PolicyVersionDetail `json:"PolicyVersion"`
}

// PolicyVersionDetail represents a policy version detail.
type PolicyVersionDetail struct {
	Document         PolicyDocument `json:"Document"`
	VersionId        string         `json:"VersionId,omitempty"`
	IsDefaultVersion bool           `json:"IsDefaultVersion,omitempty"`
	CreateDate       string         `json:"CreateDate,omitempty"`
}

// ActionResult describes how an action was evaluated.
type ActionResult struct {
	Action   string
	Allowed  bool
	Source   string
	Warnings []string
}

// ExtractedActions holds actions separated by their effect in the source policy.
type ExtractedActions struct {
	AllowActions    []string
	DenyActions     []string
	NotActionStmts  []NotActionStatement
	HasWildcards    bool
	HasConditions   bool
	HasNotResources bool
}

// NotActionStatement captures a statement using NotAction.
type NotActionStatement struct {
	Effect     string
	NotActions []string
	Resource   interface{}
	Condition  interface{}
}

// ReadStdin reads all of stdin and returns it as a byte slice.
func ReadStdin() ([]byte, error) {
	var sb strings.Builder
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// ReadFromPathOrStdin reads a file from a path, or from stdin if path is "-".
func ReadFromPathOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return ReadStdin()
	}
	return os.ReadFile(path)
}

// ExtractActions separates actions by their Effect (Allow vs Deny) in the source policy.
func ExtractActions(doc PolicyDocument) ExtractedActions {
	allowMap := make(map[string]bool)
	denyMap := make(map[string]bool)
	var notActionStmts []NotActionStatement
	hasWildcards := false
	hasConditions := false
	hasNotResources := false

	for _, stmt := range doc.Statement {
		if stmt.Condition != nil {
			hasConditions = true
		}
		if stmt.NotResource != nil {
			hasNotResources = true
		}

		if stmt.NotAction != nil {
			notActionStmts = append(notActionStmts, NotActionStatement{
				Effect:     stmt.Effect,
				NotActions: matcher.ExtractStrings(stmt.NotAction),
				Resource:   stmt.Resource,
				Condition:  stmt.Condition,
			})
			continue
		}

		if stmt.Action == nil {
			continue
		}

		target := allowMap
		if stmt.Effect == "Deny" {
			target = denyMap
		}

		switch actions := stmt.Action.(type) {
		case string:
			if matcher.IsWildcardAction(actions) {
				hasWildcards = true
			}
			target[actions] = true
		case []interface{}:
			for _, action := range actions {
				if s, ok := action.(string); ok {
					if matcher.IsWildcardAction(s) {
						hasWildcards = true
					}
					target[s] = true
				}
			}
		}
	}

	var allowList, denyList []string
	for a := range allowMap {
		allowList = append(allowList, a)
	}
	for a := range denyMap {
		denyList = append(denyList, a)
	}
	sort.Strings(allowList)
	sort.Strings(denyList)

	return ExtractedActions{
		AllowActions:    allowList,
		DenyActions:     denyList,
		NotActionStmts:  notActionStmts,
		HasWildcards:    hasWildcards,
		HasConditions:   hasConditions,
		HasNotResources: hasNotResources,
	}
}

// Warnings builds a list of human-readable caveats. plainText=true omits emoji.
func Warnings(extracted ExtractedActions, plainText bool) []string {
	prefix := "!!"
	if !plainText {
		prefix = "🟡"
	}
	var warnings []string
	if extracted.HasWildcards {
		warnings = append(warnings, fmt.Sprintf("%s  Policy contains wildcard actions (e.g. s3:* or ec2:Describe*). "+
			"This tool checks the wildcard pattern against the boundary as-is and cannot enumerate "+
			"every concrete action it covers. A wildcard may match boundary-allowed AND boundary-denied "+
			"actions simultaneously — review manually.", prefix))
	}
	if len(extracted.NotActionStmts) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%s  Policy contains %d statement(s) using NotAction. These grant (or deny) a broad "+
				"set of actions and cannot be fully evaluated without a complete AWS action catalog. "+
				"Review these statements manually (details shown below).",
			prefix, len(extracted.NotActionStmts)))
	}
	if extracted.HasConditions {
		warnings = append(warnings, fmt.Sprintf("%s  Policy contains Condition keys. This tool does not evaluate "+
			"conditions — an action may appear allowed/blocked here but behave differently at runtime "+
			"depending on request context.", prefix))
	}
	if extracted.HasNotResources {
		warnings = append(warnings, fmt.Sprintf("%s  Policy contains NotResource. Resource scope is not evaluated "+
			"by this tool.", prefix))
	}
	return warnings
}

// NullableStringSlice returns an empty slice (not nil) so JSON output is [] not null.
func NullableStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
