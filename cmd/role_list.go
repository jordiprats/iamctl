package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/spf13/cobra"
)

func newRoleListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "role-list <query>",
		Aliases: []string{"rl", "lr", "search-roles", "sr"},
		Short:   "List IAM roles whose names contain a string",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl role-list app
  iamctl role-list -1 app
  iamctl role-list --active-within-days 90 app
  iamctl role-list --output json read
  iamctl role-list --profile staging ops`,
		RunE: func(cmd *cobra.Command, args []string) error {
			query := strings.TrimSpace(args[0])
			format, _ := cmd.Flags().GetString("output")
			profile, _ := cmd.Flags().GetString("profile")
			activeWithinDays, _ := cmd.Flags().GetInt("active-within-days")
			onePerLine, _ := cmd.Flags().GetBool("one-per-line")

			if activeWithinDays < 0 {
				return fmt.Errorf("--active-within-days must be >= 0")
			}

			filters := awsiam.RoleSearchFilters{}
			if activeWithinDays > 0 {
				cutoff := time.Now().Add(-time.Duration(activeWithinDays) * 24 * time.Hour)
				filters.LastActiveAfter = &cutoff
			}

			iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
			if err != nil {
				return err
			}

			roles, err := awsiam.SearchRolesBySubstring(cmd.Context(), iamClient, query, filters)
			if err != nil {
				return err
			}

			switch format {
			case "json":
				if onePerLine {
					return fmt.Errorf("-1/--one-per-line cannot be used with --output json")
				}
				result := map[string]interface{}{
					"query":              query,
					"active_within_days": activeWithinDays,
					"matches":            roles,
					"summary":            map[string]int{"matches": len(roles)},
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))
			default:
				if onePerLine {
					for _, role := range roles {
						fmt.Println(role.Name)
					}
					return nil
				}
				if len(roles) == 0 {
					fmt.Printf("No IAM roles found matching the requested filters\n")
					return nil
				}
				for _, role := range roles {
					lastUsed := "(never/unknown)"
					if role.LastUsedAt != nil {
						lastUsed = role.LastUsedAt.UTC().Format(time.RFC3339)
					}
					fmt.Printf("- %s (%s) last-used: %s\n", role.Name, role.ARN, lastUsed)
				}
			}

			return nil
		},
	}

	cmd.Flags().String("output", "list", "Output format: list or json")
	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().Int("active-within-days", 0, "Filter matches to roles active within the last N days (0 disables filter)")
	cmd.Flags().BoolP("one-per-line", "1", false, "Print only matching role names, one per line")

	return cmd
}
