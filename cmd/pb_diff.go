package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pb-diff [policy-file]",
		Aliases: []string{"diff", "compare", "cmp"},
		Short:   "Compare policy actions against two permission boundaries",
		Long: `Loads two permission boundaries (--pb and --pb-new) and reports which Allow actions
would gain or lose access when switching from the old to the new boundary.

Policy source — specify exactly one:
  <policy-file>   Local JSON policy file, or '-' to read from stdin
  --role <name>   Fetch the role's attached managed policies from AWS`,
		Args: cobra.MaximumNArgs(1),
		Example: `  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json --output json policy.json
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json --role my-role
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json --role my-role --profile staging`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")
			pbNewFile, _ := cmd.Flags().GetString("pb-new")
			format, _ := cmd.Flags().GetString("output")
			roleName, _ := cmd.Flags().GetString("role")
			profile, _ := cmd.Flags().GetString("profile")

			if roleName == "" && len(args) == 0 {
				return fmt.Errorf("either a policy file argument or --role must be specified")
			}
			if roleName != "" && len(args) > 0 {
				return fmt.Errorf("--role and a policy file argument are mutually exclusive")
			}

			pbOld, err := boundary.LoadFromFile(pbFile)
			if err != nil {
				return fmt.Errorf("loading old permission boundary: %w", err)
			}
			pbNew, err := boundary.LoadFromFile(pbNewFile)
			if err != nil {
				return fmt.Errorf("loading new permission boundary: %w", err)
			}

			var extracted policy.ExtractedActions

			if roleName != "" {
				iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
				if err != nil {
					return err
				}
				policies, err := awsiam.FetchRolePolicies(cmd.Context(), iamClient, roleName)
				if err != nil {
					return fmt.Errorf("fetching role policies: %w", err)
				}
				if len(policies) == 0 {
					fmt.Fprintln(os.Stderr, "No managed policies attached to role")
					return nil
				}

				mergedAllow := make(map[string]bool)
				for _, policyDoc := range policies {
					ext := policy.ExtractActions(policyDoc)
					extracted.HasWildcards = extracted.HasWildcards || ext.HasWildcards
					extracted.HasConditions = extracted.HasConditions || ext.HasConditions
					extracted.HasNotResources = extracted.HasNotResources || ext.HasNotResources
					extracted.NotActionStmts = append(extracted.NotActionStmts, ext.NotActionStmts...)
					for _, a := range ext.AllowActions {
						mergedAllow[a] = true
					}
				}
				for a := range mergedAllow {
					extracted.AllowActions = append(extracted.AllowActions, a)
				}
				sort.Strings(extracted.AllowActions)
			} else {
				data, err := policy.ReadFromPathOrStdin(args[0])
				if err != nil {
					return fmt.Errorf("reading policy file: %w", err)
				}
				var doc policy.PolicyDocument
				if err := json.Unmarshal(data, &doc); err != nil {
					return fmt.Errorf("parsing policy JSON: %w", err)
				}
				extracted = policy.ExtractActions(doc)
			}

			// Classify every Allow action
			type diffEntry struct {
				Action     string
				OldAllowed bool
				NewAllowed bool
			}

			var entries []diffEntry
			for _, action := range extracted.AllowActions {
				entries = append(entries, diffEntry{
					Action:     action,
					OldAllowed: boundary.IsActionAllowed(action, pbOld),
					NewAllowed: boundary.IsActionAllowed(action, pbNew),
				})
			}

			var gained, lost, unchanged []string
			for _, e := range entries {
				switch {
				case !e.OldAllowed && e.NewAllowed:
					gained = append(gained, e.Action)
				case e.OldAllowed && !e.NewAllowed:
					lost = append(lost, e.Action)
				default:
					unchanged = append(unchanged, e.Action)
				}
			}

			switch format {
			case "json":
				warnings := policy.Warnings(extracted, true)
				result := map[string]interface{}{
					"gained":    policy.NullableStringSlice(gained),
					"lost":      policy.NullableStringSlice(lost),
					"unchanged": policy.NullableStringSlice(unchanged),
					"warnings":  warnings,
					"summary": map[string]int{
						"gained":    len(gained),
						"lost":      len(lost),
						"unchanged": len(unchanged),
					},
				}
				if roleName != "" {
					result["role"] = roleName
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))

			default: // list
				warnings := policy.Warnings(extracted, false)
				if roleName != "" {
					fmt.Fprintf(os.Stderr, "Role: %s\n\n", roleName)
				}
				printWarnings(warnings, os.Stderr)
				if len(gained) > 0 {
					fmt.Println("🟢  Newly allowed by new boundary (gained access):")
					for _, a := range gained {
						fmt.Printf("    %s\n", a)
					}
				}
				if len(lost) > 0 {
					fmt.Println("\n🔴  No longer allowed by new boundary (lost access):")
					for _, a := range lost {
						fmt.Printf("    %s\n", a)
					}
				}
				if len(unchanged) > 0 {
					fmt.Printf("\n--  Unchanged: %d action(s)\n", len(unchanged))
				}
				fmt.Printf("\nSummary: %d gained, %d lost, %d unchanged\n", len(gained), len(lost), len(unchanged))
			}

			// Exit non-zero if any access is lost
			if len(lost) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().String("pb", "", "Path to the old permission boundary file (JSON or text format), or '-' for stdin")
	_ = cmd.MarkFlagRequired("pb")

	cmd.Flags().String("pb-new", "", "Path to the new permission boundary to compare against (required)")
	_ = cmd.MarkFlagRequired("pb-new")

	cmd.Flags().String("role", "", "IAM role name to fetch managed policies from AWS (mutually exclusive with policy file argument)")
	cmd.Flags().String("profile", "", "AWS profile to use when fetching role policies")
	cmd.Flags().String("output", "list", "Output format: list or json")

	return cmd
}
