package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/spf13/cobra"
)

func newPolicyListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "policy-list <query>",
		Aliases: []string{"pl", "search-policies", "sp"},
		Short:   "List IAM managed policies whose names contain a string",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl policy-list read
  iamctl policy-list --scope local app
  iamctl policy-list --description-contains readonly read
  iamctl policy-list --description-not-contains deprecated read
  iamctl policy-list --output json --profile staging ops`,
		RunE: func(cmd *cobra.Command, args []string) error {
			query := strings.TrimSpace(args[0])
			format, _ := cmd.Flags().GetString("output")
			profile, _ := cmd.Flags().GetString("profile")
			scopeRaw, _ := cmd.Flags().GetString("scope")
			descriptionContains, _ := cmd.Flags().GetString("description-contains")
			descriptionNotContains, _ := cmd.Flags().GetString("description-not-contains")

			scope, err := parsePolicyScope(scopeRaw)
			if err != nil {
				return err
			}

			iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
			if err != nil {
				return err
			}

			filters := awsiam.PolicySearchFilters{
				DescriptionContains:    descriptionContains,
				DescriptionNotContains: descriptionNotContains,
			}

			policies, err := awsiam.SearchManagedPoliciesBySubstring(cmd.Context(), iamClient, query, scope, filters)
			if err != nil {
				return err
			}

			switch format {
			case "json":
				result := map[string]interface{}{
					"query":                    query,
					"scope":                    strings.ToLower(scopeRaw),
					"description_contains":     descriptionContains,
					"description_not_contains": descriptionNotContains,
					"matches":                  policies,
					"summary":                  map[string]int{"matches": len(policies)},
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))
			default:
				if len(policies) == 0 {
					fmt.Printf("No IAM managed policies found matching the requested filters\n")
					return nil
				}
				fmt.Printf("Found %d IAM managed policies containing %q:\n", len(policies), query)
				for _, p := range policies {
					desc := p.Description
					if desc == "" {
						desc = "(no description)"
					}
					fmt.Printf("- %s (%s)\n  description: %s\n", p.Name, p.ARN, desc)
				}
			}

			return nil
		},
	}

	cmd.Flags().String("output", "list", "Output format: list or json")
	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().String("scope", "all", "Policy scope: all, aws, or local")
	cmd.Flags().String("description-contains", "", "Filter matches to policies whose description contains this string")
	cmd.Flags().String("description-not-contains", "", "Filter matches to policies whose description does not contain this string")

	return cmd
}

func parsePolicyScope(value string) (types.PolicyScopeType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "all":
		return types.PolicyScopeTypeAll, nil
	case "aws":
		return types.PolicyScopeTypeAws, nil
	case "local":
		return types.PolicyScopeTypeLocal, nil
	default:
		return "", fmt.Errorf("invalid --scope %q (expected all, aws, or local)", value)
	}
}
