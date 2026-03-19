package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/jordiprats/iam-pb-check/pkg/boundary"
	"github.com/jordiprats/iam-pb-check/pkg/matcher"
	"github.com/spf13/cobra"
)

func newCheckActionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check-action <action> [action...]",
		Short: "Check if one or more actions are allowed by the permission boundary",
		Args:  cobra.MinimumNArgs(1),
		Example: `  iamctl check-action ec2:RunInstances
  iamctl check-action s3:PutObject s3:GetObject ec2:DescribeInstances
  iamctl check-action --pb boundary.json s3:PutObject
  aws iam get-policy-version ... | iamctl check-action --pb - ec2:RunInstances`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")

			pb, err := boundary.LoadFromFile(pbFile)
			if err != nil {
				return fmt.Errorf("loading permission boundary: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)

			anyDenied := false
			for _, action := range args {
				if matcher.IsWildcardAction(action) {
					fmt.Fprintf(os.Stderr, "🟡  '%s' contains a wildcard — result reflects pattern matching only, not full action enumeration.\n", action)
				}
				if boundary.IsActionAllowed(action, pb) {
					if pb.Policy != nil {
						fmt.Printf("🟢  %-58s ALLOWED\n", action)
					} else {
						_, matchingPatterns := matcher.MatchesAnyPattern(action, pb.Patterns)
						fmt.Printf("🟢  %-58s matches: %s\n", action, strings.Join(matchingPatterns, ", "))
					}
				} else {
					anyDenied = true
					fmt.Printf("🔴  %-58s DENIED\n", action)
				}
			}

			if anyDenied {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().String("pb", "", "Path to the permission boundary file (JSON or text format), or '-' for stdin")

	_ = cmd.MarkFlagRequired("pb")

	return cmd
}
