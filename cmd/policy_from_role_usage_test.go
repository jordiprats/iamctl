package cmd

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestBuildStatementsFromAccessDetails(t *testing.T) {
	now := time.Now()
	details := &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
			{
				ServiceNamespace:           aws.String("ec2"),
				TotalAuthenticatedEntities: aws.Int32(1),
				LastAuthenticated:          &now,
				TrackedActionsLastAccessed: []iamtypes.TrackedActionLastAccessed{
					{
						ActionName:         aws.String("CreateNetworkInterface"),
						LastAccessedEntity: aws.String("arn:aws:iam::123456789012:role/test"),
					},
					{
						ActionName:         aws.String("DescribeNetworkInterfaces"),
						LastAccessedEntity: aws.String("arn:aws:iam::123456789012:role/test"),
					},
				},
			},
			{
				ServiceNamespace:           aws.String("kms"),
				TotalAuthenticatedEntities: aws.Int32(1),
				LastAuthenticated:          &now,
				TrackedActionsLastAccessed: []iamtypes.TrackedActionLastAccessed{
					{
						ActionName:         aws.String("Decrypt"),
						LastAccessedEntity: aws.String("arn:aws:iam::123456789012:role/test"),
					},
				},
			},
		},
	}

	stmts := buildStatementsFromAccessDetails(t.Context(), nil, details, "job-123")

	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	ec2Actions, ok := stmts[0].Action.([]string)
	if !ok {
		t.Fatalf("expected []string action, got %T", stmts[0].Action)
	}
	if len(ec2Actions) != 2 {
		t.Fatalf("expected 2 ec2 actions, got %d", len(ec2Actions))
	}
	if ec2Actions[0] != "ec2:CreateNetworkInterface" {
		t.Errorf("expected ec2:CreateNetworkInterface, got %s", ec2Actions[0])
	}
	if ec2Actions[1] != "ec2:DescribeNetworkInterfaces" {
		t.Errorf("expected ec2:DescribeNetworkInterfaces, got %s", ec2Actions[1])
	}
	if stmts[0].Effect != "Allow" {
		t.Errorf("expected Allow, got %s", stmts[0].Effect)
	}
	if stmts[0].Resource != "*" {
		t.Errorf("expected *, got %v", stmts[0].Resource)
	}

	kmsActions, ok := stmts[1].Action.([]string)
	if !ok {
		t.Fatalf("expected []string action, got %T", stmts[1].Action)
	}
	if len(kmsActions) != 1 || kmsActions[0] != "kms:Decrypt" {
		t.Errorf("expected [kms:Decrypt], got %v", kmsActions)
	}
}

func TestBuildStatementsFromAccessDetails_NoActivity(t *testing.T) {
	details := &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
			{
				ServiceNamespace:           aws.String("s3"),
				TotalAuthenticatedEntities: aws.Int32(0),
			},
		},
	}

	stmts := buildStatementsFromAccessDetails(t.Context(), nil, details, "job-456")
	if len(stmts) != 0 {
		t.Fatalf("expected 0 statements for unused service, got %d", len(stmts))
	}
}

func TestBuildStatementsFromAccessDetails_NilTotalEntities(t *testing.T) {
	details := &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
			{
				ServiceNamespace: aws.String("s3"),
			},
		},
	}

	stmts := buildStatementsFromAccessDetails(t.Context(), nil, details, "job-789")
	if len(stmts) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(stmts))
	}
}

func TestBuildStatementsFromAccessDetails_NoTrackedActions(t *testing.T) {
	details := &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
			{
				ServiceNamespace:           aws.String("s3"),
				TotalAuthenticatedEntities: aws.Int32(1),
			},
		},
	}

	stmts := buildStatementsFromAccessDetails(t.Context(), nil, details, "job-abc")
	if len(stmts) != 0 {
		t.Fatalf("expected 0 statements when no tracked actions, got %d", len(stmts))
	}
}

func TestBuildStatementsFromAccessDetails_ActionWithoutEntity(t *testing.T) {
	details := &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
			{
				ServiceNamespace:           aws.String("s3"),
				TotalAuthenticatedEntities: aws.Int32(1),
				TrackedActionsLastAccessed: []iamtypes.TrackedActionLastAccessed{
					{
						ActionName: aws.String("GetObject"),
					},
					{
						ActionName:         aws.String("PutObject"),
						LastAccessedEntity: aws.String("arn:aws:iam::123456789012:role/test"),
					},
				},
			},
		},
	}

	stmts := buildStatementsFromAccessDetails(t.Context(), nil, details, "job-def")
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	actions, ok := stmts[0].Action.([]string)
	if !ok {
		t.Fatalf("expected []string, got %T", stmts[0].Action)
	}
	if len(actions) != 1 || actions[0] != "s3:PutObject" {
		t.Errorf("expected [s3:PutObject], got %v", actions)
	}
}

func TestBuildStatementsFromAccessDetails_Empty(t *testing.T) {
	details := &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus:            iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{},
	}

	stmts := buildStatementsFromAccessDetails(t.Context(), nil, details, "job-empty")
	if len(stmts) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(stmts))
	}
}

func TestValueOrEmpty_Nil(t *testing.T) {
	if got := valueOrEmpty(nil); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestValueOrEmpty_WithMessage(t *testing.T) {
	err := &iamtypes.ErrorDetails{
		Message: aws.String("something went wrong"),
	}
	if got := valueOrEmpty(err); got != "something went wrong" {
		t.Errorf("expected 'something went wrong', got %q", got)
	}
}

func TestValueOrEmpty_NilMessage(t *testing.T) {
	err := &iamtypes.ErrorDetails{}
	if got := valueOrEmpty(err); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
