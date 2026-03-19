package cmd

import "github.com/spf13/cobra"

// NewRootCmd creates the root cobra command.
func NewRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "iamctl",
		Short: "AWS IAM Swiss Army Knife",
		Long:  "Validate AWS IAM actions and policies against a permission boundary definition, generate least-privilege policies, and more.",
	}

	root.Version = version
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(newCheckActionCmd())
	root.AddCommand(newCheckPolicyCmd())
	root.AddCommand(newCheckRoleCmd())
	root.AddCommand(newCheckCfCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newPolicyFromRoleUsageCmd())
	root.AddCommand(newShrinkRolePoliciesCmd())
	root.AddCommand(GenDocsCmd(root))

	return root
}
