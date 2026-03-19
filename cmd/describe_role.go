package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/spf13/cobra"
)

func newDescribeRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "describe-role <role-name>",
		Aliases: []string{"dr"},
		Short:   "Describe an IAM role, including summary, managed policies, and inline policies",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl describe-role my-role
  iamctl describe-role --output json my-role
  iamctl describe-role --profile staging my-role`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			output, _ := cmd.Flags().GetString("output")
			roleName := args[0]

			iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
			if err != nil {
				return err
			}

			desc, err := awsiam.DescribeRole(cmd.Context(), iamClient, roleName)
			if err != nil {
				return err
			}

			switch output {
			case "json":
				out, _ := json.MarshalIndent(desc, "", "  ")
				fmt.Println(string(out))
				return nil
			case "wide":
				// Continue with human-readable describe-style output below.
			default:
				return fmt.Errorf("invalid --output %q (expected wide or json)", output)
			}

			printDescribeField("Name", desc.RoleName)
			printDescribeField("ARN", desc.ARN)
			printDescribeField("Creation Timestamp", formatDateTimeForConsole(desc.CreateDate))
			printDescribeField("Last Activity", formatLastActivity(desc.LastUsedAt))
			printDescribeField("Max Session Duration", formatSessionDuration(desc.MaxSessionDuration))
			if desc.SwitchRoleURL != "" {
				printDescribeField("Switch Role URL", desc.SwitchRoleURL)
			} else {
				printDescribeField("Switch Role URL", "(not available)")
			}

			fmt.Println("Managed Policies:")
			if len(desc.AttachedPolicies) == 0 {
				fmt.Println("  (none)")
			} else {
				for _, p := range desc.AttachedPolicies {
					fmt.Printf("  - %s\n", p.ARN)
				}
			}

			fmt.Println("Inline Policies:")
			if len(desc.InlinePolicies) == 0 {
				fmt.Println("  (none)")
				return nil
			}

			names := make([]string, 0, len(desc.InlinePolicies))
			for name := range desc.InlinePolicies {
				names = append(names, name)
			}
			sort.Strings(names)

			for _, name := range names {
				fmt.Printf("  %s:\n", name)
				out, _ := json.MarshalIndent(desc.InlinePolicies[name], "", "  ")
				fmt.Println(indentBlock(string(out), "    "))
			}

			return nil
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().String("output", "wide", "Output format: wide or json")

	return cmd
}
