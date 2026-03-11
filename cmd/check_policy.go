package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iam-pb-check/pkg/boundary"
	"github.com/jordiprats/iam-pb-check/pkg/policy"
	"github.com/spf13/cobra"
)

func newCheckPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check-policy <policy-file>",
		Short: "Check which actions in a policy are allowed or blocked by the permission boundary",
		Args:  cobra.ExactArgs(1),
		Example: `  pb-checker check-policy policy.json
  pb-checker check-policy --output json policy.json
  pb-checker check-policy --pb boundary.json --output table policy.json
  cat policy.json | pb-checker check-policy -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")
			format, _ := cmd.Flags().GetString("output")
			policyFile := args[0]

			data, err := policy.ReadFromPathOrStdin(policyFile)
			if err != nil {
				return fmt.Errorf("reading policy file: %w", err)
			}

			var doc policy.PolicyDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("parsing policy JSON: %w", err)
			}

			extracted := policy.ExtractActions(doc)
			if len(extracted.AllowActions) == 0 && len(extracted.DenyActions) == 0 && len(extracted.NotActionStmts) == 0 {
				fmt.Println("No actions found in policy")
				return nil
			}

			pb, err := boundary.LoadFromFile(pbFile)
			if err != nil {
				return fmt.Errorf("loading permission boundary: %w", err)
			}

			// Evaluate Allow actions against the permission boundary
			var allowedActions, blockedActions []string
			for _, action := range extracted.AllowActions {
				if boundary.IsActionAllowed(action, pb) {
					allowedActions = append(allowedActions, action)
				} else {
					blockedActions = append(blockedActions, action)
				}
			}
			sort.Strings(allowedActions)
			sort.Strings(blockedActions)

			// Summarise NotAction statements for display
			var notActionSummaries []string
			for _, nas := range extracted.NotActionStmts {
				summary := fmt.Sprintf("Effect=%s NotAction=[%s]", nas.Effect, strings.Join(nas.NotActions, ", "))
				if nas.Condition != nil {
					summary += " (has Condition)"
				}
				notActionSummaries = append(notActionSummaries, summary)
			}

			switch format {
			case "json":
				warnings := policy.Warnings(extracted, true)
				result := map[string]interface{}{
					"evaluation_method":     pb.EvaluationMethod,
					"allowed":               policy.NullableStringSlice(allowedActions),
					"blocked":               policy.NullableStringSlice(blockedActions),
					"skipped_deny":          policy.NullableStringSlice(extracted.DenyActions),
					"not_action_statements": policy.NullableStringSlice(notActionSummaries),
					"warnings":              warnings,
					"summary": map[string]int{
						"allowed":               len(allowedActions),
						"blocked":               len(blockedActions),
						"skipped_deny":          len(extracted.DenyActions),
						"not_action_statements": len(extracted.NotActionStmts),
					},
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))

			case "table":
				warnings := policy.Warnings(extracted, false)
				fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
				printWarnings(warnings, os.Stderr)
				fmt.Printf("%-4s %-58s %s\n", "", "ACTION", "STATUS")
				fmt.Printf("%s\n", strings.Repeat("-", 75))
				for _, a := range allowedActions {
					fmt.Printf("🟢  %-58s ALLOWED\n", a)
				}
				for _, a := range blockedActions {
					fmt.Printf("🔴  %-58s BLOCKED\n", a)
				}
				for _, a := range extracted.DenyActions {
					fmt.Printf("🟡  %-58s SKIPPED (explicitly denied by policy)\n", a)
				}
				for _, s := range notActionSummaries {
					fmt.Printf("🟠  %-58s NOTACTION (manual review needed)\n", s)
				}
				fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
					len(allowedActions), len(blockedActions), len(extracted.DenyActions), len(extracted.NotActionStmts))

			default: // list
				warnings := policy.Warnings(extracted, false)
				fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
				printWarnings(warnings, os.Stderr)
				if len(allowedActions) > 0 {
					fmt.Println("🟢  Allowed actions:")
					for _, a := range allowedActions {
						fmt.Printf("    %s\n", a)
					}
				}
				if len(blockedActions) > 0 {
					fmt.Println("\n🔴  Blocked actions (not allowed by permission boundary):")
					for _, a := range blockedActions {
						fmt.Printf("    %s\n", a)
					}
				}
				if len(extracted.DenyActions) > 0 {
					fmt.Println("\n🟡  Skipped actions (explicitly denied by policy, irrelevant to boundary check):")
					for _, a := range extracted.DenyActions {
						fmt.Printf("    %s\n", a)
					}
				}
				if len(notActionSummaries) > 0 {
					fmt.Println("\n🟠  NotAction statements (requires manual review):")
					for _, s := range notActionSummaries {
						fmt.Printf("    %s\n", s)
					}
				}
				fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
					len(allowedActions), len(blockedActions), len(extracted.DenyActions), len(extracted.NotActionStmts))
			}

			if len(blockedActions) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().String("pb", "pb.json", "Path to the permission boundary file (JSON or text format), or '-' for stdin")
	cmd.Flags().String("output", "list", "Output format: list, json, or table")
	return cmd
}
