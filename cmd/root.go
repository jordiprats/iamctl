package cmd

import "github.com/spf13/cobra"

// NewRootCmd creates the root cobra command.
func NewRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "pb-checker",
		Short: "AWS IAM Permission Boundary Checker",
		Long:  "Validate AWS IAM actions and policies against a permission boundary definition.",
	}

	root.Version = version
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(newCheckActionCmd())
	root.AddCommand(newCheckPolicyCmd())
	root.AddCommand(newCheckRoleCmd())
	root.AddCommand(newDiffCmd())

	return root
}
