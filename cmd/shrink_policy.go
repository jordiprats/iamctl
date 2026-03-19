package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/matcher"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

func newShrinkRolePoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shrink-role-policies <role-name>",
		Short: "Generate a minimal policy for a role by removing unused actions from its attached policies",
		Long: `Fetches all managed policies attached to the given role, then uses service last accessed
data (at ACTION_LEVEL granularity) to identify which actions are actually being used.

Outputs a single consolidated policy containing only the actions the role has really used.
Deny statements, NotAction statements, Conditions, Resources, and Sids are preserved as-is.`,
		Args: cobra.ExactArgs(1),
		Example: `  iamctl shrink-role-policies my-role
  iamctl shrink-role-policies --profile staging my-role`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			quiet, _ := cmd.Flags().GetBool("quiet")
			roleName := args[0]

			ctx := cmd.Context()

			var opts []func(*config.LoadOptions) error
			opts = append(opts, config.WithRetryMode(aws.RetryModeAdaptive))
			opts = append(opts, config.WithRetryMaxAttempts(10))
			if profile != "" {
				opts = append(opts, config.WithSharedConfigProfile(profile))
			}
			cfg, err := config.LoadDefaultConfig(ctx, opts...)
			if err != nil {
				return fmt.Errorf("loading AWS config: %w", err)
			}

			client := iam.NewFromConfig(cfg)

			// Get the role ARN
			roleOut, err := client.GetRole(ctx, &iam.GetRoleInput{
				RoleName: &roleName,
			})
			if err != nil {
				return fmt.Errorf("getting role %q: %w", roleName, err)
			}
			roleArn := *roleOut.Role.Arn

			// Fetch and merge the role's attached policies
			if !quiet {
				fmt.Fprintf(os.Stderr, "Fetching policies for role: %s\n", roleArn)
			}
			policies, err := boundary.FetchRolePolicies(ctx, client, roleName)
			if err != nil {
				return fmt.Errorf("fetching role policies: %w", err)
			}
			if len(policies) == 0 {
				return fmt.Errorf("no managed policies attached to role %q", roleName)
			}
			if !quiet {
				fmt.Fprintf(os.Stderr, "Found %d attached policy/policies\n", len(policies))
			}
			doc := mergePolicyDocs(policies)

			// Fetch service last accessed data
			accessedActions, accessedDetails, err := fetchAccessedActions(ctx, client, roleArn)
			if err != nil {
				return err
			}

			if !quiet {
				fmt.Fprintf(os.Stderr, "Actions observed in use: %d\n", len(accessedActions))
				printTrackingPeriod(accessedDetails)
			}

			// Shrink the policy
			shrunk, removed := shrinkDocument(doc, accessedActions)

			if !quiet {
				if len(removed) > 0 {
					fmt.Fprintf(os.Stderr, "\nRemoved %d unused action(s):\n", len(removed))
					for _, a := range removed {
						fmt.Fprintf(os.Stderr, "  - %s\n", a)
					}
					fmt.Fprintln(os.Stderr)
				} else {
					fmt.Fprintln(os.Stderr, "No unused actions found — policy is already minimal.")
				}
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(shrunk)
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use")
	cmd.Flags().BoolP("quiet", "q", false, "Suppress informational output, print only the policy JSON")

	return cmd
}

// fetchAccessedActions retrieves ACTION_LEVEL last accessed data for an ARN
// and returns a set of lowercase "service:Action" strings that were actually used.
func fetchAccessedActions(ctx context.Context, client *iam.Client, arn string) (map[string]bool, *iam.GetServiceLastAccessedDetailsOutput, error) {
	genOut, err := client.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
		Arn:         &arn,
		Granularity: iamtypes.AccessAdvisorUsageGranularityTypeActionLevel,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("generating service last accessed details: %w", err)
	}

	jobID := *genOut.JobId

	var details *iam.GetServiceLastAccessedDetailsOutput
	for {
		details, err = client.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId: &jobID,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("getting service last accessed details: %w", err)
		}
		if details.JobStatus == iamtypes.JobStatusTypeCompleted {
			break
		}
		if details.JobStatus == iamtypes.JobStatusTypeFailed {
			return nil, nil, fmt.Errorf("job failed: %s", valueOrEmpty(details.Error))
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}

	accessed := make(map[string]bool)

	// Collect all pages
	services := details.ServicesLastAccessed
	marker := details.Marker
	for details.IsTruncated {
		page, err := client.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId:  &jobID,
			Marker: marker,
		})
		if err != nil {
			break
		}
		services = append(services, page.ServicesLastAccessed...)
		marker = page.Marker
		details.IsTruncated = page.IsTruncated
	}

	for _, svc := range services {
		if svc.TotalAuthenticatedEntities == nil || *svc.TotalAuthenticatedEntities == 0 {
			continue
		}
		if svc.TrackedActionsLastAccessed == nil {
			continue
		}
		for _, action := range svc.TrackedActionsLastAccessed {
			if action.LastAccessedEntity != nil {
				key := strings.ToLower(fmt.Sprintf("%s:%s", *svc.ServiceNamespace, *action.ActionName))
				accessed[key] = true
			}
		}
	}

	return accessed, details, nil
}

// shrinkDocument removes unused Allow actions from a policy document.
// Deny statements, NotAction statements, and non-Action statements are kept as-is.
// Returns the shrunk document and a list of removed actions.
func shrinkDocument(doc policy.PolicyDocument, accessed map[string]bool) (policy.PolicyDocument, []string) {
	var kept []policy.Statement
	var removed []string

	for _, stmt := range doc.Statement {
		// Keep Deny statements untouched
		if stmt.Effect == "Deny" {
			kept = append(kept, stmt)
			continue
		}

		// Keep NotAction statements untouched
		if stmt.NotAction != nil {
			kept = append(kept, stmt)
			continue
		}

		// Skip statements without Action
		if stmt.Action == nil {
			kept = append(kept, stmt)
			continue
		}

		actions := matcher.ExtractStrings(stmt.Action)
		var surviving []string
		for _, a := range actions {
			if isActionAccessed(a, accessed) {
				surviving = append(surviving, a)
			} else {
				removed = append(removed, a)
			}
		}

		if len(surviving) == 0 {
			// Entire statement pruned
			continue
		}

		// Rebuild the statement with only surviving actions
		newStmt := stmt
		if len(surviving) == 1 {
			newStmt.Action = surviving[0]
		} else {
			// Convert to []interface{} to match the original JSON marshaling
			iface := make([]interface{}, len(surviving))
			for i, s := range surviving {
				iface[i] = s
			}
			newStmt.Action = iface
		}
		kept = append(kept, newStmt)
	}

	return policy.PolicyDocument{
		Version:   doc.Version,
		Statement: kept,
	}, removed
}

// isActionAccessed checks if a policy action (which may contain wildcards)
// matches any of the actually-accessed actions.
func isActionAccessed(policyAction string, accessed map[string]bool) bool {
	lower := strings.ToLower(policyAction)

	// Direct match (common case)
	if accessed[lower] {
		return true
	}

	// If the policy action has wildcards, check if any accessed action matches the pattern
	if matcher.IsWildcardAction(policyAction) {
		re, err := matcher.IamPatternToRegex(policyAction)
		if err != nil {
			return true // keep on error, be conservative
		}
		for a := range accessed {
			if re.MatchString(a) {
				return true
			}
		}
		return false
	}

	return false
}

// mergePolicyDocs merges multiple policy documents into one.
func mergePolicyDocs(policies map[string]policy.PolicyDocument) policy.PolicyDocument {
	var allStatements []policy.Statement
	for _, doc := range policies {
		allStatements = append(allStatements, doc.Statement...)
	}
	return policy.PolicyDocument{
		Version:   "2012-10-17",
		Statement: allStatements,
	}
}
