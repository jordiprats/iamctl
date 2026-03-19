package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

func newPolicyFromRoleUsageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "policy-from-role-usage <role-name>",
		Aliases: []string{"activity-policy", "policy-from-usage", "pfu"},
		Short:   "Generate a least-privilege policy based on a role's actual usage (service last accessed data)",
		Args:    cobra.ExactArgs(1),
		Example: `  iamctl policy-from-role-usage my-role
  iamctl policy-from-role-usage --profile staging my-role`,
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

			// Start the service last accessed details job
			genOut, err := client.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
				Arn:         &roleArn,
				Granularity: iamtypes.AccessAdvisorUsageGranularityTypeActionLevel,
			})
			if err != nil {
				return fmt.Errorf("generating service last accessed details: %w", err)
			}

			jobID := *genOut.JobId
			if !quiet {
				fmt.Fprintf(os.Stderr, "Analyzing activity for role: %s\n", roleArn)
			}

			// Poll until the job completes
			var details *iam.GetServiceLastAccessedDetailsOutput
			for {
				details, err = client.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
					JobId: &jobID,
				})
				if err != nil {
					return fmt.Errorf("getting service last accessed details: %w", err)
				}
				if details.JobStatus == iamtypes.JobStatusTypeCompleted {
					break
				}
				if details.JobStatus == iamtypes.JobStatusTypeFailed {
					return fmt.Errorf("job failed: %s", valueOrEmpty(details.Error))
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(1 * time.Second):
				}
			}

			if !quiet {
				printTrackingPeriod(details)
			}

			statements := buildStatementsFromAccessDetails(ctx, client, details, jobID)

			if len(statements) == 0 {
				return fmt.Errorf("no activity found for role: %s", roleArn)
			}

			doc := policy.PolicyDocument{
				Version:   "2012-10-17",
				Statement: statements,
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(doc)
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use")
	cmd.Flags().BoolP("quiet", "q", false, "Suppress informational output, print only the policy JSON")

	return cmd
}

func buildStatementsFromAccessDetails(ctx context.Context, client *iam.Client, details *iam.GetServiceLastAccessedDetailsOutput, jobID string) []policy.Statement {
	var statements []policy.Statement

	// Paginate through all service last accessed details
	services := details.ServicesLastAccessed

	// Also fetch remaining pages if the response was truncated
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

		var actions []string
		for _, action := range svc.TrackedActionsLastAccessed {
			if action.LastAccessedEntity != nil {
				actionName := fmt.Sprintf("%s:%s", *svc.ServiceNamespace, *action.ActionName)
				actions = append(actions, actionName)
			}
		}

		if len(actions) > 0 {
			stmt := policy.Statement{
				Effect:   "Allow",
				Action:   actions,
				Resource: "*",
			}
			statements = append(statements, stmt)
		}
	}

	return statements
}

func valueOrEmpty(err *iamtypes.ErrorDetails) string {
	if err == nil {
		return ""
	}
	if err.Message != nil {
		return *err.Message
	}
	return ""
}

// printTrackingPeriod prints the time range covered by the service last accessed data.
func printTrackingPeriod(details *iam.GetServiceLastAccessedDetailsOutput) {
	var oldest, newest time.Time

	for _, svc := range details.ServicesLastAccessed {
		if svc.LastAuthenticated == nil {
			continue
		}
		t := *svc.LastAuthenticated
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
		if newest.IsZero() || t.After(newest) {
			newest = t
		}
	}

	if !oldest.IsZero() {
		days := int(time.Since(oldest).Hours() / 24)
		fmt.Fprintf(os.Stderr, "Tracking period: %s to %s (~%d days)\n",
			oldest.Format("2006-01-02"), newest.Format("2006-01-02"), days)
	}
	fmt.Fprintf(os.Stderr, "Note: AWS IAM tracks action-level usage for up to 400 days\n\n")
}
