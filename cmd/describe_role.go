package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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
			if len(desc.AttachedPolicyNames) == 0 {
				fmt.Println("  (none)")
			} else {
				for _, name := range desc.AttachedPolicyNames {
					fmt.Printf("  - %s\n", name)
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

func formatDateTimeForConsole(t time.Time) string {
	local := t.Local()
	_, offsetSec := local.Zone()
	sign := "+"
	if offsetSec < 0 {
		sign = "-"
		offsetSec = -offsetSec
	}
	hours := offsetSec / 3600
	minutes := (offsetSec % 3600) / 60
	return fmt.Sprintf("%s (UTC%s%02d:%02d)", local.Format("January 2, 2006, 15:04"), sign, hours, minutes)
}

func formatLastActivity(lastUsedAt *time.Time) string {
	if lastUsedAt == nil {
		return "No recent activity"
	}
	delta := time.Since(*lastUsedAt)
	if delta < time.Minute {
		return "just now"
	}
	if delta < time.Hour {
		m := int(delta / time.Minute)
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	}
	if delta < 24*time.Hour {
		h := int(delta / time.Hour)
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	}
	days := int(delta / (24 * time.Hour))
	if days == 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

func formatSessionDuration(seconds int32) string {
	d := time.Duration(seconds) * time.Second
	h := int(d / time.Hour)
	if d%time.Hour == 0 {
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	m := int(d / time.Minute)
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

func printDescribeField(label, value string) {
	fmt.Printf("%-22s %s\n", label+":", value)
}

func indentBlock(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
