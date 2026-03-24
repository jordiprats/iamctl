package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newPbCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "pb-check [policy-file]",
		Aliases: []string{
			"check", "pbc",
			// Legacy command aliases
			"pb-check-action", "check-action", "ca",
			"pb-check-policy", "check-policy", "cp",
			"pb-check-role", "check-role", "cr",
			"pb-check-cf", "check-cf", "check-cloudformation", "ccf",
		},
		Short: "Check actions, policies, roles, or CloudFormation templates against a permission boundary",
		Long: `Evaluate IAM actions against a permission boundary.

Sources (exactly one required):
  [policy-file]            Local policy JSON file, or '-' to read from stdin
  --action <action>        Check specific actions directly (can be repeated)
  --role <name>            Fetch policies from a live AWS IAM role
  --cf-template <file>     Parse a CloudFormation template

When checking a policy file, additional policies can be included with --policy-file
or --managed-policy. When using --cf-template, use --resource to target a specific
IAM resource by logical ID.

Supported CloudFormation resource types:
  - AWS::IAM::Role (managed + inline policies)
  - AWS::IAM::Policy (standalone policy)
  - AWS::IAM::ManagedPolicy (standalone managed policy)

The permission boundary (--pb) is required for action and policy checks.
For role checks, if --pb is omitted the role's own permission boundary is fetched from AWS.
For CloudFormation checks, if --pb is omitted it is resolved from the template.

Backward compatibility:
  When invoked as check-action/pb-check-action/ca, positional arguments are
  treated as action names (like the old pb-check-action command).
  When invoked as check-role/pb-check-role/cr, the first positional argument
  is treated as the role name (like the old pb-check-role command).
  When invoked as check-cf/pb-check-cf/ccf, the first positional argument
  is treated as the CloudFormation template file.`,
		Args: cobra.ArbitraryArgs,
		Example: `  # Check specific actions
  iamctl pb-check --action ec2:RunInstances --pb boundary.json
  iamctl pb-check --action s3:PutObject --action s3:GetObject --pb boundary.json

  # Check a policy file
  iamctl pb-check --pb boundary.json policy.json
  iamctl pb-check --pb boundary.json --policy-file extra.json policy.json
  iamctl pb-check --pb boundary.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess
  iamctl pb-check --pb boundary.json --output json policy.json

  # Check a live AWS role
  iamctl pb-check --role my-role
  iamctl pb-check --role my-role --pb boundary.json --output json
  iamctl pb-check --role my-role --profile staging

  # Check a CloudFormation template
  iamctl pb-check --cf-template template.yaml
  iamctl pb-check --cf-template template.yaml --resource LambdaRole
  iamctl pb-check --cf-template template.yaml --pb boundary.json --output sarif`,
		RunE: func(cmd *cobra.Command, args []string) error {
			actions, _ := cmd.Flags().GetStringSlice("action")
			roleName, _ := cmd.Flags().GetString("role")
			cfTemplate, _ := cmd.Flags().GetString("cf-template")

			// Detect legacy alias invocation and re-interpret positional args
			calledAs := cmd.CalledAs()
			switch calledAs {
			case "pb-check-action", "check-action", "ca":
				// Legacy: positional args are actions
				actions = append(actions, args...)
				args = nil
			case "pb-check-role", "check-role", "cr":
				// Legacy: first positional arg is role name
				if roleName == "" && len(args) > 0 {
					roleName = args[0]
					args = args[1:]
				}
			case "pb-check-cf", "check-cf", "check-cloudformation", "ccf":
				// Legacy: first positional arg is template file
				if cfTemplate == "" && len(args) > 0 {
					cfTemplate = args[0]
					args = args[1:]
				}
			}

			policyFile := ""
			if len(args) > 0 {
				policyFile = args[0]
			}

			// Determine how many explicit source flags are set
			modeCount := 0
			if len(actions) > 0 {
				modeCount++
			}
			if roleName != "" {
				modeCount++
			}
			if cfTemplate != "" {
				modeCount++
			}

			if modeCount > 1 {
				return fmt.Errorf("specify only one source: --action, --role, or --cf-template")
			}

			// Positional arg conflicts with explicit source flags
			if policyFile != "" && modeCount > 0 {
				return fmt.Errorf("a policy file argument cannot be combined with --action, --role, or --cf-template")
			}

			// Policy-mode-only flags
			policyFiles, _ := cmd.Flags().GetStringSlice("policy-file")
			managedPolicies, _ := cmd.Flags().GetStringSlice("managed-policy")
			if modeCount > 0 && (len(policyFiles) > 0 || len(managedPolicies) > 0) {
				return fmt.Errorf("--policy-file and --managed-policy can only be used when checking a policy file")
			}

			// CF-mode-only flag
			resource, _ := cmd.Flags().GetString("resource")
			if resource != "" && cfTemplate == "" {
				return fmt.Errorf("--resource can only be used with --cf-template")
			}

			// If no explicit mode flag is set, we're in policy mode
			isPolicyMode := modeCount == 0
			if isPolicyMode && policyFile == "" && len(policyFiles) == 0 && len(managedPolicies) == 0 {
				return fmt.Errorf("at least one of a policy file, --policy-file, --managed-policy, --action, --role, or --cf-template must be specified")
			}

			// Dispatch to the appropriate mode
			if len(actions) > 0 {
				return runCheckAction(cmd, actions)
			}
			if roleName != "" {
				return runCheckRole(cmd, roleName)
			}
			if cfTemplate != "" {
				return runCheckCf(cmd, cfTemplate)
			}
			return runCheckPolicy(cmd, policyFile)
		},
	}

	// Common flags
	cmd.Flags().String("pb", "", "Path to the permission boundary file (JSON or text format), or '-' for stdin")
	cmd.Flags().String("output", "list", "Output format: list, json, table, or sarif (sarif only with --cf-template)")
	cmd.Flags().String("profile", "", "AWS profile to use")

	// Source flags
	cmd.Flags().StringSlice("action", nil, "Action(s) to check directly (can be repeated)")
	cmd.Flags().String("role", "", "AWS IAM role name to check")
	cmd.Flags().String("cf-template", "", "Path to a CloudFormation template file")

	// Policy-mode flags
	cmd.Flags().StringSlice("policy-file", nil, "Path to an additional policy file (can be repeated)")
	cmd.Flags().StringSlice("managed-policy", nil, "ARN of a managed policy to fetch from AWS (can be repeated)")

	// CF-mode flags
	cmd.Flags().String("resource", "", "Logical ID of a specific IAM resource (only with --cf-template)")

	return cmd
}
