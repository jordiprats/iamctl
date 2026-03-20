package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

func newMergeRolePoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "merge-role-policies <role-name>",
		Aliases: []string{"mrp", "merge-policies"},
		Short:   "Merge all managed policies attached to a role into a single unified policy JSON",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl merge-role-policies my-role
  iamctl merge-role-policies --quiet my-role
  iamctl merge-role-policies --profile staging my-role`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			quiet, _ := cmd.Flags().GetBool("quiet")
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

			// Ensure a canonical Version is set
			if merged.Version == "" {
				merged.Version = "2012-10-17"
			}

			// Deduplicate statements to avoid redundant entries
			merged = policy.PolicyDocument{
				Version:   merged.Version,
				Statement: dedupeStatements(merged.Statement),
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(merged)
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().BoolP("quiet", "q", false, "Suppress informational output, print only the policy JSON")

	return cmd
}
