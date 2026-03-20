package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

// filterDenyStatements returns a new slice with all Deny-effect statements removed.
func filterDenyStatements(stmts []policy.Statement) []policy.Statement {
	var kept []policy.Statement
	for _, stmt := range stmts {
		if !strings.EqualFold(stmt.Effect, "Deny") {
			kept = append(kept, stmt)
		}
	}
	return kept
}

func newMergeRolePoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "merge-role-policies <role-name>",
		Aliases: []string{"mrp", "merge-policies"},
		Short:   "Merge all managed policies attached to a role into a single unified policy JSON",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl merge-role-policies my-role
  iamctl merge-role-policies --quiet my-role
  iamctl merge-role-policies --ignore-deny my-role
  iamctl merge-role-policies --strict my-role
  iamctl merge-role-policies --profile staging my-role`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			quiet, _ := cmd.Flags().GetBool("quiet")
			ignoreDeny, _ := cmd.Flags().GetBool("ignore-deny")
			strict, _ := cmd.Flags().GetBool("strict")
			roleName := args[0]

			iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
			if err != nil {
				return err
			}

			if !quiet {
				fmt.Fprintf(os.Stderr, "Fetching policies for role: %s\n", roleName)
			}

			policies, err := awsiam.FetchRolePolicies(cmd.Context(), iamClient, roleName)
			if err != nil {
				return fmt.Errorf("fetching role policies: %w", err)
			}

			if len(policies) == 0 {
				return fmt.Errorf("no managed policies attached to role %q", roleName)
			}

			if !quiet {
				policyNames := make([]string, 0, len(policies))
				for name := range policies {
					policyNames = append(policyNames, name)
				}
				sort.Strings(policyNames)
				fmt.Fprintf(os.Stderr, "Merging %d policy/policies:\n", len(policies))
				for _, name := range policyNames {
					fmt.Fprintf(os.Stderr, "  - %s\n", name)
				}
			}

			merged := mergePolicyDocs(policies)

			// Filter out Deny statements if requested
			if ignoreDeny {
				merged.Statement = filterDenyStatements(merged.Statement)
			}

			// Compact equivalent statements (normalize + merge duplicates)
			var stmts []policy.Statement
			if strict {
				stmts = compactStatements(merged.Statement)
			} else {
				stmts = dedupeStatements(merged.Statement)
			}
			merged = policy.PolicyDocument{
				Version:   merged.Version,
				Statement: stmts,
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(merged)
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().BoolP("quiet", "q", false, "Suppress informational output, print only the policy JSON")
	cmd.Flags().Bool("ignore-deny", false, "Omit Deny statements from the output policy")
	cmd.Flags().Bool("strict", false, "Compact equivalent statements by normalizing and merging actions with identical Effect/Resource/Condition")

	return cmd
}
