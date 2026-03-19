package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

func newCheckRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pb-check-role <role-name>",
		Aliases: []string{"check-role", "cr"},
		Short:   "Check an IAM role's managed-policy actions against a permission boundary",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl pb-check-role my-role
  iamctl pb-check-role --pb boundary.json --output json my-role
  iamctl pb-check-role --profile staging my-role`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("output")
			profile, _ := cmd.Flags().GetString("profile")
			roleName := args[0]

			iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
			if err != nil {
				return err
			}

			// If --pb was explicitly provided, load from file; otherwise fetch the role's own PB
			var pb *boundary.PermissionBoundary
			if cmd.Flags().Changed("pb") {
				pbFile, _ := cmd.Flags().GetString("pb")
				pb, err = boundary.LoadFromFile(pbFile)
				if err != nil {
					return fmt.Errorf("loading permission boundary: %w", err)
				}
			} else {
				pb, err = awsiam.FetchRoleBoundary(cmd.Context(), iamClient, roleName)
				if err != nil {
					return err
				}
			}

			policies, err := awsiam.FetchRolePolicies(cmd.Context(), iamClient, roleName)
			if err != nil {
				return fmt.Errorf("fetching role policies: %w", err)
			}

			if len(policies) == 0 {
				fmt.Println("No managed policies attached to role")
				return nil
			}

			// Merge all actions from all attached policies
			mergedAllow := make(map[string]string) // action -> policy name
			mergedDeny := make(map[string]string)
			var allNotActionStmts []policy.NotActionStatement
			hasWildcards := false
			hasConditions := false
			hasNotResources := false

			for policyName, policyDoc := range policies {
				extracted := policy.ExtractActions(policyDoc)
				if extracted.HasWildcards {
					hasWildcards = true
				}
				if extracted.HasConditions {
					hasConditions = true
				}
				if extracted.HasNotResources {
					hasNotResources = true
				}
				for _, a := range extracted.AllowActions {
					mergedAllow[a] = policyName
				}
				for _, a := range extracted.DenyActions {
					mergedDeny[a] = policyName
				}
				allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
			}

			mergedExtracted := policy.ExtractedActions{
				HasWildcards:    hasWildcards,
				HasConditions:   hasConditions,
				HasNotResources: hasNotResources,
				NotActionStmts:  allNotActionStmts,
			}

			// Sort actions
			var allowActions []string
			for a := range mergedAllow {
				allowActions = append(allowActions, a)
			}
			sort.Strings(allowActions)

			var denyActions []string
			for a := range mergedDeny {
				denyActions = append(denyActions, a)
			}
			sort.Strings(denyActions)
			mergedExtracted.AllowActions = allowActions
			mergedExtracted.DenyActions = denyActions

			// Evaluate against boundary
			var allowedActions, blockedActions []string
			for _, action := range allowActions {
				if boundary.IsActionAllowed(action, pb) {
					allowedActions = append(allowedActions, action)
				} else {
					blockedActions = append(blockedActions, action)
				}
			}
			sort.Strings(allowedActions)
			sort.Strings(blockedActions)

			var notActionSummaries []string
			for _, nas := range allNotActionStmts {
				summary := fmt.Sprintf("Effect=%s NotAction=[%s]", nas.Effect, strings.Join(nas.NotActions, ", "))
				if nas.Condition != nil {
					summary += " (has Condition)"
				}
				notActionSummaries = append(notActionSummaries, summary)
			}

			switch format {
			case "json":
				warnings := policy.Warnings(mergedExtracted, true)
				// Build per-policy breakdown
				policyNames := make([]string, 0, len(policies))
				for name := range policies {
					policyNames = append(policyNames, name)
				}
				sort.Strings(policyNames)

				blockedDetail := make([]map[string]string, 0, len(blockedActions))
				for _, a := range blockedActions {
					blockedDetail = append(blockedDetail, map[string]string{
						"action": a,
						"policy": mergedAllow[a],
					})
				}
				result := map[string]interface{}{
					"role":                  roleName,
					"evaluation_method":     pb.EvaluationMethod,
					"attached_policies":     policyNames,
					"allowed":               policy.NullableStringSlice(allowedActions),
					"blocked":               blockedDetail,
					"skipped_deny":          policy.NullableStringSlice(denyActions),
					"not_action_statements": policy.NullableStringSlice(notActionSummaries),
					"warnings":              warnings,
					"summary": map[string]int{
						"attached_policies":     len(policies),
						"allowed":               len(allowedActions),
						"blocked":               len(blockedActions),
						"skipped_deny":          len(denyActions),
						"not_action_statements": len(allNotActionStmts),
					},
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))

			default: // list
				warnings := policy.Warnings(mergedExtracted, false)
				fmt.Fprintf(os.Stderr, "Role: %s\n", roleName)
				fmt.Fprintf(os.Stderr, "Evaluation method: %s\n", pb.EvaluationMethod)
				fmt.Fprintf(os.Stderr, "Attached managed policies: %d\n", len(policies))
				for name := range policies {
					fmt.Fprintf(os.Stderr, "  - %s\n", name)
				}
				fmt.Fprintln(os.Stderr)
				printWarnings(warnings, os.Stderr)
				if len(allowedActions) > 0 {
					fmt.Println("🟢  Allowed actions:")
					for _, a := range allowedActions {
						fmt.Printf("    %-58s (from %s)\n", a, mergedAllow[a])
					}
				}
				if len(blockedActions) > 0 {
					fmt.Println("\n🔴  Blocked actions (not allowed by permission boundary):")
					for _, a := range blockedActions {
						fmt.Printf("    %-58s (from %s)\n", a, mergedAllow[a])
					}
				}
				if len(denyActions) > 0 {
					fmt.Println("\n🟡  Skipped actions (explicitly denied by policy):")
					for _, a := range denyActions {
						fmt.Printf("    %-58s (from %s)\n", a, mergedDeny[a])
					}
				}
				if len(notActionSummaries) > 0 {
					fmt.Println("\n🟠  NotAction statements (requires manual review):")
					for _, s := range notActionSummaries {
						fmt.Printf("    %s\n", s)
					}
				}
				fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
					len(allowedActions), len(blockedActions), len(denyActions), len(allNotActionStmts))
			}

			if len(blockedActions) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().String("pb", "", "Path to the permission boundary file (if omitted, fetches the role's own PB from AWS)")
	cmd.Flags().String("output", "list", "Output format: list or json")
	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")

	return cmd
}
