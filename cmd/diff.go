package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jordiprats/iam-pb-check/pkg/boundary"
	"github.com/jordiprats/iam-pb-check/pkg/policy"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <policy-file>",
		Short: "Compare policy actions against two permission boundaries to show what changes",
		Long: `Loads two permission boundaries (--pb and --pb-new) and reports which Allow actions
in the given policy would gain or lose access when switching from the old to the new boundary.`,
		Args: cobra.ExactArgs(1),
		Example: `  iamctl diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json --output json policy.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")
			pbNewFile, _ := cmd.Flags().GetString("pb-new")
			format, _ := cmd.Flags().GetString("output")
			policyFile := args[0]

			if pbNewFile == "" {
				return fmt.Errorf("--pb-new is required for the diff subcommand")
			}

			data, err := policy.ReadFromPathOrStdin(policyFile)
			if err != nil {
				return fmt.Errorf("reading policy file: %w", err)
			}

			var doc policy.PolicyDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("parsing policy JSON: %w", err)
			}

			extracted := policy.ExtractActions(doc)

			pbOld, err := boundary.LoadFromFile(pbFile)
			if err != nil {
				return fmt.Errorf("loading old permission boundary: %w", err)
			}

			pbNew, err := boundary.LoadFromFile(pbNewFile)
			if err != nil {
				return fmt.Errorf("loading new permission boundary: %w", err)
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
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))

			default: // list
				warnings := policy.Warnings(extracted, false)
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

	cmd.Flags().String("pb", "", "Path to the permission boundary file (JSON or text format), or '-' for stdin")
	_ = cmd.MarkFlagRequired("pb")

	cmd.Flags().String("pb-new", "", "Path to the new permission boundary to compare against (required)")
	_ = cmd.MarkFlagRequired("pb-new")

	cmd.Flags().String("output", "list", "Output format: list or json")

	return cmd
}
