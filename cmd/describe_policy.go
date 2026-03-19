package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/spf13/cobra"
)

func newDescribePolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "describe-policy <policy-arn>",
		Aliases: []string{"dp"},
		Short:   "Describe a managed policy and show its JSON document",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl describe-policy arn:aws:iam::aws:policy/ReadOnlyAccess
  iamctl describe-policy --json-policy arn:aws:iam::123456789012:policy/MyPolicy
  iamctl describe-policy --profile staging arn:aws:iam::123456789012:policy/MyPolicy`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			jsonPolicyOnly, _ := cmd.Flags().GetBool("json-policy")
			policyARN := args[0]

			iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
			if err != nil {
				return err
			}

			desc, err := awsiam.DescribeManagedPolicy(cmd.Context(), iamClient, policyARN)
			if err != nil {
				return err
			}

			if jsonPolicyOnly {
				out, _ := json.MarshalIndent(desc.Document, "", "  ")
				fmt.Println(string(out))
				return nil
			}

			printDescribeField("Name", desc.Name)
			printDescribeField("ARN", desc.ARN)
			if desc.IsAWSManaged {
				printDescribeField("Type", "AWS managed")
			} else {
				printDescribeField("Type", "Customer managed")
			}
			if desc.Description == "" {
				printDescribeField("Description", "(none)")
			} else {
				printDescribeField("Description", desc.Description)
			}
			if desc.Path == "" {
				printDescribeField("Path", "/")
			} else {
				printDescribeField("Path", desc.Path)
			}
			if desc.CreateDate != nil {
				printDescribeField("Creation Timestamp", formatDateTimeForConsole(*desc.CreateDate))
			} else {
				printDescribeField("Creation Timestamp", "(unknown)")
			}
			if desc.UpdateDate != nil {
				printDescribeField("Updated Timestamp", formatDateTimeForConsole(*desc.UpdateDate))
			} else {
				printDescribeField("Updated Timestamp", "(unknown)")
			}
			printDescribeField("Default Version", desc.DefaultVersionID)

			fmt.Println("Policy Document:")
			out, _ := json.MarshalIndent(desc.Document, "", "  ")
			fmt.Println(indentBlock(string(out), "  "))

			return nil
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().Bool("json-policy", false, "Print only the policy JSON document")

	return cmd
}
