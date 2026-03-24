package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/cfn"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

// filterDenyStatements returns a new slice with all Deny-effect statements removed.
func filterDenyStatements(stmts []policy.Statement) []policy.Statement {
	var kept []policy.Statement
	for _, stmt := range stmts {
		if !strings.EqualFold(stmt.Effect, "Deny") {
			kept = append(kept, stmt)
		}
	}
	return kept
}

func newMergePoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "merge-policies",
		Aliases: []string{"mp", "merge-role-policies", "mrp", "merge-cf-policies", "mcp"},
		Short:   "Merge IAM policies from a role or CloudFormation template into a single unified policy JSON",
		Long: `Merge all IAM policy statements into a single policy document.

Sources (exactly one required):
  --role <name>            Fetch managed policies from a live AWS IAM role
  --cf-template <file>     Parse a CloudFormation template and extract policies

When using --cf-template, use --resource to target a specific IAM resource by logical ID.
When not specified, all IAM resources in the template are merged together.

Supported CloudFormation resource types:
  - AWS::IAM::Role (managed + inline policies)
  - AWS::IAM::Policy (standalone policy)
  - AWS::IAM::ManagedPolicy (standalone managed policy)

Managed policy ARNs are fetched from AWS. Intrinsic functions (Fn::Join, Ref, Fn::Sub)
in ARN values are resolved automatically using STS GetCallerIdentity.`,
		Args: cobra.NoArgs,
		Example: `  # From a live AWS role
  iamctl merge-policies --role my-role
  iamctl merge-policies --role my-role --quiet
  iamctl merge-policies --role my-role --ignore-deny
  iamctl merge-policies --role my-role --strict --profile staging

  # From a CloudFormation template
  iamctl merge-policies --cf-template template.yaml
  iamctl merge-policies --cf-template template.yaml --resource LambdaRole
  iamctl merge-policies --cf-template template.yaml --ignore-deny --strict`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			quiet, _ := cmd.Flags().GetBool("quiet")
			ignoreDeny, _ := cmd.Flags().GetBool("ignore-deny")
			strict, _ := cmd.Flags().GetBool("strict")
			roleName, _ := cmd.Flags().GetString("role")
			cfTemplate, _ := cmd.Flags().GetString("cf-template")
			resource, _ := cmd.Flags().GetString("resource")

			if roleName == "" && cfTemplate == "" {
				return fmt.Errorf("specify a source: --role <name> or --cf-template <file>")
			}
			if roleName != "" && cfTemplate != "" {
				return fmt.Errorf("specify only one source: --role or --cf-template, not both")
			}
			if resource != "" && cfTemplate == "" {
				return fmt.Errorf("--resource can only be used with --cf-template")
			}

			var allPolicies map[string]policy.PolicyDocument

			if roleName != "" {
				policies, err := mergeFromRole(cmd, roleName, profile, quiet)
				if err != nil {
					return err
				}
				allPolicies = policies
			} else {
				policies, err := mergeFromCfTemplate(cmd, cfTemplate, profile, resource, quiet)
				if err != nil {
					return err
				}
				allPolicies = policies
			}

			if !quiet {
				policyNames := make([]string, 0, len(allPolicies))
				for name := range allPolicies {
					policyNames = append(policyNames, name)
				}
				sort.Strings(policyNames)
				fmt.Fprintf(os.Stderr, "Merging %d policy/policies:\n", len(allPolicies))
				for _, name := range policyNames {
					fmt.Fprintf(os.Stderr, "  - %s\n", name)
				}
			}

			merged := mergePolicyDocs(allPolicies)

			if ignoreDeny {
				merged.Statement = filterDenyStatements(merged.Statement)
			}

			var stmts []policy.Statement
			if strict {
				stmts = compactStatements(merged.Statement)
			} else {
				stmts = dedupeStatements(merged.Statement)
			}
			merged = policy.PolicyDocument{
				Version:   merged.Version,
				Statement: stmts,
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(merged)
		},
	}

	cmd.Flags().String("role", "", "AWS IAM role name to fetch policies from")
	cmd.Flags().String("cf-template", "", "Path to a CloudFormation template file")
	cmd.Flags().String("resource", "", "Logical ID of a specific IAM resource to extract (only with --cf-template)")
	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().BoolP("quiet", "q", false, "Suppress informational output, print only the policy JSON")
	cmd.Flags().Bool("ignore-deny", false, "Omit Deny statements from the output policy")
	cmd.Flags().Bool("strict", false, "Compact equivalent statements by normalizing and merging actions with identical Effect/Resource/Condition")

	return cmd
}

// mergeFromRole fetches all managed policies from a live AWS IAM role.
func mergeFromRole(cmd *cobra.Command, roleName, profile string, quiet bool) (map[string]policy.PolicyDocument, error) {
	iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
	if err != nil {
		return nil, err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Fetching policies for role: %s\n", roleName)
	}

	policies, err := awsiam.FetchRolePolicies(cmd.Context(), iamClient, roleName)
	if err != nil {
		return nil, fmt.Errorf("fetching role policies: %w", err)
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("no managed policies attached to role %q", roleName)
	}

	return policies, nil
}

// mergeFromCfTemplate extracts policies from a CloudFormation template.
func mergeFromCfTemplate(cmd *cobra.Command, templateFile, profile, resource string, quiet bool) (map[string]policy.PolicyDocument, error) {
	tmpl, err := cfn.ParseTemplate(templateFile)
	if err != nil {
		return nil, err
	}

	roles, err := cfn.ExtractIAMRoles(tmpl)
	if err != nil {
		return nil, err
	}

	policies, err := cfn.ExtractIAMPolicies(tmpl)
	if err != nil {
		return nil, err
	}

	// Filter to a specific resource if requested
	if resource != "" {
		var filteredRoles []cfn.IAMRole
		for _, r := range roles {
			if r.LogicalID == resource {
				filteredRoles = append(filteredRoles, r)
			}
		}
		var filteredPolicies []cfn.IAMPolicyResource
		for _, p := range policies {
			if p.LogicalID == resource {
				filteredPolicies = append(filteredPolicies, p)
			}
		}
		if len(filteredRoles) == 0 && len(filteredPolicies) == 0 {
			var available []string
			for _, r := range roles {
				available = append(available, r.LogicalID)
			}
			for _, p := range policies {
				available = append(available, p.LogicalID)
			}
			return nil, fmt.Errorf("resource %q not found; available IAM resources: %s", resource, strings.Join(available, ", "))
		}
		roles = filteredRoles
		policies = filteredPolicies
	}

	if len(roles) == 0 && len(policies) == 0 {
		return nil, fmt.Errorf("no IAM role or policy resources found in template")
	}

	allPolicies := make(map[string]policy.PolicyDocument)

	for _, role := range roles {
		rolePolicies, err := collectRolePolicies(cmd, role, profile, quiet)
		if err != nil {
			return nil, fmt.Errorf("collecting policies for role %q: %w", role.LogicalID, err)
		}
		for name, doc := range rolePolicies {
			allPolicies[role.LogicalID+"/"+name] = doc
		}
	}

	for _, pol := range policies {
		allPolicies[pol.LogicalID] = pol.PolicyDocument
	}

	if len(allPolicies) == 0 {
		return nil, fmt.Errorf("no policies found in template")
	}

	return allPolicies, nil
}

// collectRolePolicies gathers all inline and managed policy documents for a CF role.
func collectRolePolicies(cmd *cobra.Command, role cfn.IAMRole, profile string, quiet bool) (map[string]policy.PolicyDocument, error) {
	ctx := cmd.Context()
	result := make(map[string]policy.PolicyDocument)

	// Add inline policies directly
	for name, doc := range role.Properties.InlinePolicies {
		result[name+" (inline)"] = doc
	}

	// Resolve intrinsic ManagedPolicyArns
	if len(role.Properties.ManagedPolicyArnsRaw) > 0 {
		pseudoParams, err := awsiam.GetAWSPseudoParams(ctx, profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not resolve intrinsic ManagedPolicyArns: %v\n", err)
		} else {
			for _, raw := range role.Properties.ManagedPolicyArnsRaw {
				resolved, err := cfn.ResolveIntrinsic(raw, pseudoParams)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: skipping unresolvable ManagedPolicyArn: %v\n", err)
					continue
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "Resolved ManagedPolicyArn: %s\n", resolved)
				}
				role.Properties.ManagedPolicyArns = append(role.Properties.ManagedPolicyArns, resolved)
			}
		}
	}

	// Fetch managed policies from AWS
	if len(role.Properties.ManagedPolicyArns) > 0 {
		iamClient, err := awsiam.NewIAMClient(ctx, profile)
		if err != nil {
			return nil, err
		}

		for _, arn := range role.Properties.ManagedPolicyArns {
			if !quiet {
				fmt.Fprintf(os.Stderr, "Fetching managed policy: %s\n", arn)
			}
			doc, err := awsiam.FetchManagedPolicy(ctx, iamClient, arn)
			if err != nil {
				return nil, fmt.Errorf("fetching managed policy %q: %w", arn, err)
			}
			policyName := arn
			if parts := strings.Split(arn, "/"); len(parts) > 0 {
				policyName = parts[len(parts)-1]
			}
			result[policyName] = *doc
		}
	}

	return result, nil
}
