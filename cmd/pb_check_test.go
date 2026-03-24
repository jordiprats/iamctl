package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// executeCommand runs a cobra command with the given args and returns stdout, stderr, and error.
func executeCommand(root *cobra.Command, args ...string) (string, error) {
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestPbCheck_NoSource(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check")
	if err == nil {
		t.Fatal("expected error when no source is specified")
	}
}

func TestPbCheck_MultipleSources(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--action", "s3:GetObject", "--role", "my-role", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when multiple sources are specified")
	}
}

func TestPbCheck_PolicyFileWithRole(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "policy.json", "--role", "my-role", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when policy file is combined with --role")
	}
}

func TestPbCheck_PolicyFileWithCfTemplate(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "policy.json", "--cf-template", "tmpl.yaml", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when policy file is combined with --cf-template")
	}
}

func TestPbCheck_PolicyFileFlagsWithRole(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--role", "my-role", "--policy-file", "extra.json", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --policy-file is used with --role")
	}
}

func TestPbCheck_ManagedPolicyWithAction(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--action", "s3:GetObject", "--managed-policy", "arn:aws:iam::aws:policy/test", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --managed-policy is used with --action")
	}
}

func TestPbCheck_ResourceWithoutCf(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "policy.json", "--resource", "MyRole", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --resource is used without --cf-template")
	}
}

func TestPbCheck_ActionRequiresPb(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--action", "s3:GetObject")
	if err == nil {
		t.Fatal("expected error when --pb is not specified for action check")
	}
}

func TestPbCheck_PolicyRequiresPb(t *testing.T) {
	root := NewRootCmd("test")
	policyFile := filepath.Join("..", "testdata", "test-policy.json")
	_, err := executeCommand(root, "pb-check", policyFile)
	if err == nil {
		t.Fatal("expected error when --pb is not specified for policy check")
	}
}

func TestPbCheck_ActionMode_AllAllowed(t *testing.T) {
	// Use the simple allow PB which allows s3/ec2/iam actions
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	// Capture stdout to check output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"pb-check", "--action", "s3:GetObject", "--action", "s3:PutObject", "--pb", pbFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output == "" {
		t.Fatal("expected some output")
	}
}

func TestPbCheck_CfMode_NoTemplate(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--cf-template", "nonexistent.yaml", "--pb", filepath.Join("..", "testdata", "test-pb-simple-allow.json"))
	if err == nil {
		t.Fatal("expected error for nonexistent template file")
	}
}

func TestPbCheck_LegacyAliases(t *testing.T) {
	// Verify legacy aliases are registered by checking the command can be found
	root := NewRootCmd("test")
	cmd, _, err := root.Find([]string{"check-action"})
	if err != nil {
		t.Fatalf("check-action alias not found: %v", err)
	}
	if cmd.Name() != "pb-check" {
		t.Errorf("expected pb-check command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"check-policy"})
	if err != nil {
		t.Fatalf("check-policy alias not found: %v", err)
	}
	if cmd.Name() != "pb-check" {
		t.Errorf("expected pb-check command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"check-role"})
	if err != nil {
		t.Fatalf("check-role alias not found: %v", err)
	}
	if cmd.Name() != "pb-check" {
		t.Errorf("expected pb-check command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"check-cf"})
	if err != nil {
		t.Fatalf("check-cf alias not found: %v", err)
	}
	if cmd.Name() != "pb-check" {
		t.Errorf("expected pb-check command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"pb-check-action"})
	if err != nil {
		t.Fatalf("pb-check-action alias not found: %v", err)
	}
	if cmd.Name() != "pb-check" {
		t.Errorf("expected pb-check command, got %s", cmd.Name())
	}
}

func TestPbCheck_PolicyMode_WithPolicyFile(t *testing.T) {
	// Create a policy that only uses actions allowed by the simple PB
	// (s3:GetObject, s3:ListBuckets, s3:PutObject, ec2:Describe*, iam:Get*, iam:List*)
	// to avoid os.Exit(1) from blocked actions
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:PutObject"],
			"Resource": "*"
		}]
	}`
	tmpFile := filepath.Join(t.TempDir(), "allowed-policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"pb-check", "--pb", pbFile, tmpFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected some output from policy check")
	}
}
