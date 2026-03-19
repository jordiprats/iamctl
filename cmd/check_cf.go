package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/cfn"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

func newCheckCfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "check-cf <template-file>",
		Aliases: []string{"check-cloudformation", "ccf"},
		Short:   "Parse a CloudFormation template and check IAM roles and policies against the permission boundary",
		Long: `Parse a CloudFormation template, extract IAM roles and standalone IAM policies,
fetch managed policies from AWS, and evaluate all actions against the permission boundary.

Supported resource types:
  - AWS::IAM::Role (managed + inline policies)
  - AWS::IAM::Policy (standalone policy)
  - AWS::IAM::ManagedPolicy (standalone managed policy)

The permission boundary is resolved in order:
  1. --pb flag (explicit file)
  2. PermissionsBoundary property from roles in the template (fetched from AWS by ARN)
  3. PermissionsBoundary with intrinsic functions (resolved using STS caller identity)

For standalone policies (AWS::IAM::Policy, AWS::IAM::ManagedPolicy), --pb is required.

Managed policy ARNs from ManagedPolicyArns are fetched from AWS.
Intrinsic functions (Fn::Join, Ref, Fn::Sub) in ARN values are resolved
automatically using STS GetCallerIdentity for the AWS account ID.
Inline policies from the Policies property are parsed directly.`,
		Args: cobra.ExactArgs(1),
		Example: `  iamctl check-cf template.yaml
  iamctl check-cf --pb boundary.json template.yaml
  iamctl check-cf --resource LambdaRole template.yaml
  iamctl check-cf --profile staging --output json template.yaml
  iamctl check-cf --pb boundary.json --resource MyPolicy template.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("output")
			profile, _ := cmd.Flags().GetString("profile")
			resource, _ := cmd.Flags().GetString("resource")
			templateFile := args[0]

			tmpl, err := cfn.ParseTemplate(templateFile)
			if err != nil {
				return err
			}

			roles, err := cfn.ExtractIAMRoles(tmpl)
			if err != nil {
				return err
			}

			policies, err := cfn.ExtractIAMPolicies(tmpl)
			if err != nil {
				return err
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
					return fmt.Errorf("resource %q not found; available IAM resources: %s", resource, strings.Join(available, ", "))
				}
				roles = filteredRoles
				policies = filteredPolicies
			}

			if len(roles) == 0 && len(policies) == 0 {
				fmt.Println("No IAM role or policy resources found in template")
				return nil
			}

			hasBlocked := false
			sectionIdx := 0
			for _, role := range roles {
				if sectionIdx > 0 {
					fmt.Println()
					fmt.Println(strings.Repeat("=", 80))
					fmt.Println()
				}
				blocked, err := checkCfRole(cmd, role, format, profile)
				if err != nil {
					return fmt.Errorf("checking role %q: %w", role.LogicalID, err)
				}
				if blocked {
					hasBlocked = true
				}
				sectionIdx++
			}

			for _, pol := range policies {
				if sectionIdx > 0 {
					fmt.Println()
					fmt.Println(strings.Repeat("=", 80))
					fmt.Println()
				}
				blocked, err := checkCfPolicy(cmd, pol, format)
				if err != nil {
					return fmt.Errorf("checking policy %q: %w", pol.LogicalID, err)
				}
				if blocked {
					hasBlocked = true
				}
				sectionIdx++
			}

			if hasBlocked {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().String("pb", "", "Path to the permission boundary file (if omitted, resolves from template)")
	cmd.Flags().String("output", "list", "Output format: list or json")
	cmd.Flags().String("profile", "", "AWS profile to use")
	cmd.Flags().String("resource", "", "Logical ID of a specific IAM resource to check (role or policy)")

	return cmd
}

func checkCfRole(cmd *cobra.Command, role cfn.IAMRole, format, profile string) (bool, error) {
	ctx := cmd.Context()

	// Create IAM client if we need to fetch anything from AWS
	needsAWS := len(role.Properties.ManagedPolicyArns) > 0 || len(role.Properties.ManagedPolicyArnsRaw) > 0
	if !cmd.Flags().Changed("pb") && (role.Properties.PermissionBoundary != "" || role.Properties.PermissionBoundaryRaw != nil) {
		needsAWS = true
	}

	var iamClient boundary.IAMClient
	if needsAWS {
		var err error
		iamClient, err = boundary.NewIAMClient(ctx, profile)
		if err != nil {
			return false, err
		}
	}

	// Resolve permission boundary
	var pb *boundary.PermissionBoundary
	if cmd.Flags().Changed("pb") {
		pbFile, _ := cmd.Flags().GetString("pb")
		var err error
		pb, err = boundary.LoadFromFile(pbFile)
		if err != nil {
			return false, fmt.Errorf("loading permission boundary: %w", err)
		}
	} else if role.Properties.PermissionBoundary != "" {
		// Fetch the PB from AWS using the ARN in the template
		pbArn := role.Properties.PermissionBoundary
		fmt.Fprintf(os.Stderr, "Fetching permission boundary from template ARN: %s\n", pbArn)
		var err error
		pb, err = boundary.FetchManagedPolicyAsBoundary(ctx, iamClient, pbArn)
		if err != nil {
			return false, fmt.Errorf("fetching permission boundary %q: %w", pbArn, err)
		}
	} else if role.Properties.PermissionBoundaryRaw != nil {
		// Resolve intrinsic function using AWS pseudo-parameters
		fmt.Fprintf(os.Stderr, "Resolving PermissionsBoundary intrinsic function...\n")
		pseudoParams, err := boundary.GetAWSPseudoParams(ctx, profile)
		if err != nil {
			return false, fmt.Errorf("fetching AWS context for intrinsic resolution: %w (use --pb to provide it manually)", err)
		}
		pbArn, err := cfn.ResolveIntrinsic(role.Properties.PermissionBoundaryRaw, pseudoParams)
		if err != nil {
			return false, fmt.Errorf("resolving PermissionsBoundary intrinsic for role %q: %w (use --pb to provide it manually)", role.LogicalID, err)
		}
		fmt.Fprintf(os.Stderr, "Resolved permission boundary ARN: %s\n", pbArn)
		if iamClient == nil {
			iamClient, err = boundary.NewIAMClient(ctx, profile)
			if err != nil {
				return false, err
			}
		}
		pb, err = boundary.FetchManagedPolicyAsBoundary(ctx, iamClient, pbArn)
		if err != nil {
			return false, fmt.Errorf("fetching permission boundary %q: %w", pbArn, err)
		}
	} else {
		return false, fmt.Errorf("role %q has no PermissionsBoundary in template and --pb was not provided", role.LogicalID)
	}

	// Collect all policy actions
	mergedAllow := make(map[string]string) // action -> source name
	mergedDeny := make(map[string]string)
	var allNotActionStmts []policy.NotActionStatement
	hasWildcards := false
	hasConditions := false
	hasNotResources := false

	// Process inline policies from the template
	for policyName, doc := range role.Properties.InlinePolicies {
		extracted := policy.ExtractActions(doc)
		if extracted.HasWildcards {
			hasWildcards = true
		}
		if extracted.HasConditions {
			hasConditions = true
		}
		if extracted.HasNotResources {
			hasNotResources = true
		}
		for _, a := range extracted.AllowActions {
			mergedAllow[a] = policyName + " (inline)"
		}
		for _, a := range extracted.DenyActions {
			mergedDeny[a] = policyName + " (inline)"
		}
		allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
	}

	// Fetch and process managed policies from AWS
	var managedPolicyNames []string

	// Resolve any intrinsic function ARNs in ManagedPolicyArns
	if len(role.Properties.ManagedPolicyArnsRaw) > 0 {
		pseudoParams, err := boundary.GetAWSPseudoParams(ctx, profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not resolve intrinsic ManagedPolicyArns: %v\n", err)
		} else {
			for _, raw := range role.Properties.ManagedPolicyArnsRaw {
				resolved, err := cfn.ResolveIntrinsic(raw, pseudoParams)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: skipping unresolvable ManagedPolicyArn: %v\n", err)
					continue
				}
				fmt.Fprintf(os.Stderr, "Resolved ManagedPolicyArn: %s\n", resolved)
				role.Properties.ManagedPolicyArns = append(role.Properties.ManagedPolicyArns, resolved)
			}
		}
	}

	for _, arn := range role.Properties.ManagedPolicyArns {
		fmt.Fprintf(os.Stderr, "Fetching managed policy: %s\n", arn)
		doc, err := boundary.FetchManagedPolicy(ctx, iamClient, arn)
		if err != nil {
			return false, fmt.Errorf("fetching managed policy %q: %w", arn, err)
		}
		// Derive a short display name from the ARN
		policyName := arn
		if parts := strings.Split(arn, "/"); len(parts) > 0 {
			policyName = parts[len(parts)-1]
		}
		managedPolicyNames = append(managedPolicyNames, policyName)

		extracted := policy.ExtractActions(*doc)
		if extracted.HasWildcards {
			hasWildcards = true
		}
		if extracted.HasConditions {
			hasConditions = true
		}
		if extracted.HasNotResources {
			hasNotResources = true
		}
		for _, a := range extracted.AllowActions {
			mergedAllow[a] = policyName
		}
		for _, a := range extracted.DenyActions {
			mergedDeny[a] = policyName
		}
		allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
	}

	mergedExtracted := policy.ExtractedActions{
		HasWildcards:    hasWildcards,
		HasConditions:   hasConditions,
		HasNotResources: hasNotResources,
		NotActionStmts:  allNotActionStmts,
	}

	// Sort actions
	var allowActions []string
	for a := range mergedAllow {
		allowActions = append(allowActions, a)
	}
	sort.Strings(allowActions)

	var denyActions []string
	for a := range mergedDeny {
		denyActions = append(denyActions, a)
	}
	sort.Strings(denyActions)
	mergedExtracted.AllowActions = allowActions
	mergedExtracted.DenyActions = denyActions

	totalPolicies := len(role.Properties.InlinePolicies) + len(role.Properties.ManagedPolicyArns)
	if totalPolicies == 0 {
		fmt.Fprintf(os.Stderr, "Role %s: no policies found\n", role.LogicalID)
		return false, nil
	}

	// Evaluate against boundary
	var allowedActions, blockedActions []string
	for _, action := range allowActions {
		if boundary.IsActionAllowed(action, pb) {
			allowedActions = append(allowedActions, action)
		} else {
			blockedActions = append(blockedActions, action)
		}
	}
	sort.Strings(allowedActions)
	sort.Strings(blockedActions)

	var notActionSummaries []string
	for _, nas := range allNotActionStmts {
		summary := fmt.Sprintf("Effect=%s NotAction=[%s]", nas.Effect, strings.Join(nas.NotActions, ", "))
		if nas.Condition != nil {
			summary += " (has Condition)"
		}
		notActionSummaries = append(notActionSummaries, summary)
	}

	// Build combined policy list for display
	var allPolicyNames []string
	for name := range role.Properties.InlinePolicies {
		allPolicyNames = append(allPolicyNames, name+" (inline)")
	}
	allPolicyNames = append(allPolicyNames, managedPolicyNames...)
	sort.Strings(allPolicyNames)

	switch format {
	case "json":
		warnings := policy.Warnings(mergedExtracted, true)
		blockedDetail := make([]map[string]string, 0, len(blockedActions))
		for _, a := range blockedActions {
			blockedDetail = append(blockedDetail, map[string]string{
				"action": a,
				"source": mergedAllow[a],
			})
		}
		result := map[string]interface{}{
			"resource":              role.LogicalID,
			"evaluation_method":     pb.EvaluationMethod,
			"policies":              allPolicyNames,
			"allowed":               policy.NullableStringSlice(allowedActions),
			"blocked":               blockedDetail,
			"skipped_deny":          policy.NullableStringSlice(denyActions),
			"not_action_statements": policy.NullableStringSlice(notActionSummaries),
			"warnings":              warnings,
			"summary": map[string]int{
				"inline_policies":       len(role.Properties.InlinePolicies),
				"managed_policies":      len(role.Properties.ManagedPolicyArns),
				"allowed":               len(allowedActions),
				"blocked":               len(blockedActions),
				"skipped_deny":          len(denyActions),
				"not_action_statements": len(allNotActionStmts),
			},
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default: // list
		warnings := policy.Warnings(mergedExtracted, false)
		fmt.Fprintf(os.Stderr, "Resource: %s (AWS::IAM::Role)\n", role.LogicalID)
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n", pb.EvaluationMethod)
		fmt.Fprintf(os.Stderr, "Policies: %d inline, %d managed\n",
			len(role.Properties.InlinePolicies), len(role.Properties.ManagedPolicyArns))
		for _, name := range allPolicyNames {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		fmt.Fprintln(os.Stderr)
		printWarnings(warnings, os.Stderr)
		if len(allowedActions) > 0 {
			fmt.Println("🟢  Allowed actions:")
			for _, a := range allowedActions {
				fmt.Printf("    %-58s (from %s)\n", a, mergedAllow[a])
			}
		}
		if len(blockedActions) > 0 {
			fmt.Println("\n🔴  Blocked actions (not allowed by permission boundary):")
			for _, a := range blockedActions {
				fmt.Printf("    %-58s (from %s)\n", a, mergedAllow[a])
			}
		}
		if len(denyActions) > 0 {
			fmt.Println("\n🟡  Skipped actions (explicitly denied by policy):")
			for _, a := range denyActions {
				fmt.Printf("    %-58s (from %s)\n", a, mergedDeny[a])
			}
		}
		if len(notActionSummaries) > 0 {
			fmt.Println("\n🟠  NotAction statements (requires manual review):")
			for _, s := range notActionSummaries {
				fmt.Printf("    %s\n", s)
			}
		}
		fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
			len(allowedActions), len(blockedActions), len(denyActions), len(allNotActionStmts))
	}

	return len(blockedActions) > 0, nil
}

func checkCfPolicy(cmd *cobra.Command, pol cfn.IAMPolicyResource, format string) (bool, error) {
	if !cmd.Flags().Changed("pb") {
		return false, fmt.Errorf("policy %q (%s) requires --pb to specify a permission boundary", pol.LogicalID, pol.Type)
	}

	pbFile, _ := cmd.Flags().GetString("pb")
	pb, err := boundary.LoadFromFile(pbFile)
	if err != nil {
		return false, fmt.Errorf("loading permission boundary: %w", err)
	}

	extracted := policy.ExtractActions(pol.PolicyDocument)

	if len(extracted.AllowActions) == 0 && len(extracted.DenyActions) == 0 && len(extracted.NotActionStmts) == 0 {
		fmt.Fprintf(os.Stderr, "Resource %s (%s): no actions found\n", pol.LogicalID, pol.Type)
		return false, nil
	}

	var allowedActions, blockedActions []string
	for _, action := range extracted.AllowActions {
		if boundary.IsActionAllowed(action, pb) {
			allowedActions = append(allowedActions, action)
		} else {
			blockedActions = append(blockedActions, action)
		}
	}
	sort.Strings(allowedActions)
	sort.Strings(blockedActions)

	var notActionSummaries []string
	for _, nas := range extracted.NotActionStmts {
		summary := fmt.Sprintf("Effect=%s NotAction=[%s]", nas.Effect, strings.Join(nas.NotActions, ", "))
		if nas.Condition != nil {
			summary += " (has Condition)"
		}
		notActionSummaries = append(notActionSummaries, summary)
	}

	switch format {
	case "json":
		warnings := policy.Warnings(extracted, true)
		blockedDetail := make([]map[string]string, 0, len(blockedActions))
		for _, a := range blockedActions {
			blockedDetail = append(blockedDetail, map[string]string{
				"action": a,
			})
		}
		result := map[string]interface{}{
			"resource":              pol.LogicalID,
			"resource_type":         pol.Type,
			"evaluation_method":     pb.EvaluationMethod,
			"allowed":               policy.NullableStringSlice(allowedActions),
			"blocked":               blockedDetail,
			"skipped_deny":          policy.NullableStringSlice(extracted.DenyActions),
			"not_action_statements": policy.NullableStringSlice(notActionSummaries),
			"warnings":              warnings,
			"summary": map[string]int{
				"allowed":               len(allowedActions),
				"blocked":               len(blockedActions),
				"skipped_deny":          len(extracted.DenyActions),
				"not_action_statements": len(extracted.NotActionStmts),
			},
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default: // list
		warnings := policy.Warnings(extracted, false)
		fmt.Fprintf(os.Stderr, "Resource: %s (%s)\n", pol.LogicalID, pol.Type)
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n", pb.EvaluationMethod)
		fmt.Fprintln(os.Stderr)
		printWarnings(warnings, os.Stderr)
		if len(allowedActions) > 0 {
			fmt.Println("🟢  Allowed actions:")
			for _, a := range allowedActions {
				fmt.Printf("    %s\n", a)
			}
		}
		if len(blockedActions) > 0 {
			fmt.Println("\n🔴  Blocked actions (not allowed by permission boundary):")
			for _, a := range blockedActions {
				fmt.Printf("    %s\n", a)
			}
		}
		if len(extracted.DenyActions) > 0 {
			fmt.Println("\n🟡  Skipped actions (explicitly denied by policy):")
			for _, a := range extracted.DenyActions {
				fmt.Printf("    %s\n", a)
			}
		}
		if len(notActionSummaries) > 0 {
			fmt.Println("\n🟠  NotAction statements (requires manual review):")
			for _, s := range notActionSummaries {
				fmt.Printf("    %s\n", s)
			}
		}
		fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
			len(allowedActions), len(blockedActions), len(extracted.DenyActions), len(extracted.NotActionStmts))
	}

	return len(blockedActions) > 0, nil
}
