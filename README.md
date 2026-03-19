# iamctl — IAM Inspection and Permission-Boundary Analysis

A command-line tool for inspecting **AWS IAM roles and policies**, validating access against **permission boundary policies**, generating least-privilege policies from actual role usage, and more.

## Overview

This tool allows you to:

1. **Permission Boundary Action Check** (`pb-check-action`): Verify if one or more AWS actions are allowed by a permission boundary.
2. **Permission Boundary Policy Validation** (`pb-check-policy`): Analyze all actions in a local policy file or AWS managed policies and identify which are allowed vs blocked by a permission boundary.
3. **Permission Boundary Role Check** (`pb-check-role`): Fetch all managed policies attached to an **IAM role** and evaluate them against a permission boundary.
4. **Describe Role** (`describe-role`): Show role summary details, switch role link, managed policies, and inline policy JSON.
5. **Describe Policy** (`describe-policy`): Show managed policy metadata and its JSON document.
6. **Role List** (`role-list`): List IAM roles whose name contains a given string, with optional last-activity filtering.
7. **Policy List** (`policy-list`): List IAM managed policies whose name contains a given string, with optional description filters.
8. **Permission Boundary CloudFormation Check** (`pb-check-cf`): Analyze IAM roles and policies from a **CloudFormation template** against a permission boundary.
9. **Permission Boundary Diff** (`pb-diff`): Compare a policy against two permission boundaries to see what access would be gained or lost.
10. **Policy from Role Usage** (`policy-from-role-usage`): Generate a least-privilege policy based on a role's actual usage (service last accessed data).
11. **Shrink Role Policies** (`shrink-role-policies`): Take a role's existing attached policies and remove unused actions based on actual usage.

## Installation

### Build from Source

```bash
git clone https://github.com/jprats/iamctl
cd iamctl
go build -o iamctl .
```

Or run directly:

```bash
go run . <command> [options]
```

## Usage

### Commands

#### `pb-check-action` — Check Actions Against a Permission Boundary

Verify if one or more AWS actions are allowed by your permission boundary.

```bash
iamctl pb-check-action --pb <boundary-file> <action> [action...]
```

**Options:**
- `--pb <file>` **(required)**: Path to permission boundary file (JSON or text format), or `-` for stdin

**Examples:**

```bash
# Check if ec2:RunInstances is allowed
iamctl pb-check-action --pb pb.json ec2:RunInstances

# Check multiple actions at once
iamctl pb-check-action --pb pb.json s3:PutObject s3:GetObject ec2:DescribeInstances

# Read boundary from stdin
aws iam get-policy-version ... | iamctl pb-check-action --pb - ec2:RunInstances
```

**Exit Codes:**
- `0`: All actions are allowed by the permission boundary
- `1`: One or more actions are denied

---

#### `pb-check-policy` — Validate IAM Policy Against a Permission Boundary

Analyze all actions in a local policy file and/or AWS managed policies, and determine which are allowed or blocked by the permission boundary.

```bash
iamctl pb-check-policy --pb <boundary-file> [policy-file] [options]
```

At least one of a local policy file or `--managed-policy` must be specified. When both are provided, actions from all sources are merged.

**Options:**
- `--pb <file>` **(required)**: Path to permission boundary file (JSON or text format), or `-` for stdin
- `--output <format>`: Output format — `list`, `json`, or `table` (default: `list`)
- `--managed-policy <arn>`: ARN of a managed policy to fetch from AWS (can be specified multiple times)
- `--profile <name>`: AWS profile to use when fetching managed policies

**Examples:**

```bash
# Analyze a local policy file
iamctl pb-check-policy --pb pb.json policy.json

# JSON output for programmatic use
iamctl pb-check-policy --pb pb.json --output json policy.json

# Table format for easy reading
iamctl pb-check-policy --pb pb.json --output table policy.json

# Check an AWS managed policy by ARN
iamctl pb-check-policy --pb pb.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess

# Combine multiple managed policies
iamctl pb-check-policy --pb pb.json \
  --managed-policy arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \
  --managed-policy arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess

# Combine a local file with managed policies
iamctl pb-check-policy --pb pb.json \
  --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess \
  custom-policy.json

# Read policy from stdin
cat policy.json | iamctl pb-check-policy --pb pb.json -
```

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked

---

#### `pb-check-role` — Check an IAM Role Against a Permission Boundary

Fetch all managed policies attached to an IAM role and evaluate them against the permission boundary. If `--pb` is omitted, the tool automatically fetches the role's own permission boundary from AWS.

```bash
iamctl pb-check-role [options] <role-name>
```

**Options:**
- `--pb <file>`: Path to permission boundary file (if omitted, fetches the role's own PB from AWS)
- `--output <format>`: Output format — `list` or `json` (default: `list`)
- `--profile <name>`: AWS profile to use

**Examples:**

```bash
# Check a role (auto-fetches its permission boundary)
iamctl pb-check-role my-role

# Use a specific boundary file instead
iamctl pb-check-role --pb boundary.json my-role

# JSON output with a specific AWS profile
iamctl pb-check-role --profile staging --output json my-role
```

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked

---

#### `describe-role` — Describe an IAM Role

Show role summary details similar to the AWS console, plus managed policy names and inline policy JSON documents.

```bash
iamctl describe-role [options] <role-name>
```

**Options:**
- `--profile <name>`: AWS profile to use
- `--output <format>`: Output format — `wide` or `json` (default: `wide`)

**Examples:**

```bash
# Describe a role
iamctl describe-role my-role

# JSON output
iamctl describe-role --output json my-role

# Use a specific profile
iamctl describe-role --profile staging my-role
```

---

#### `describe-policy` — Describe a Managed Policy

Show managed policy metadata and the default version JSON policy document.

```bash
iamctl describe-policy [options] <policy-arn>
```

**Options:**
- `--profile <name>`: AWS profile to use
- `--json-policy`: Print only the policy JSON document

**Examples:**

```bash
# Describe AWS managed policy
iamctl describe-policy arn:aws:iam::aws:policy/ReadOnlyAccess

# Print only policy JSON
iamctl describe-policy --json-policy arn:aws:iam::123456789012:policy/MyPolicy
```

---

#### `role-list` — List IAM Roles

Search IAM roles in the account whose role names contain a case-insensitive substring.

```bash
iamctl role-list [options] <query>
```

**Options:**
- `--output <format>`: Output format — `list` or `json` (default: `list`)
- `--profile <name>`: AWS profile to use
- `--active-within-days <n>`: Filter roles active within the last N days
- `-1, --one-per-line`: Print only matching role names, one per line

**Examples:**

```bash
# List roles containing "app"
iamctl role-list app

# Print matching role names only (one per line)
iamctl role-list -1 app

# Include only roles active in the last 90 days
iamctl role-list --active-within-days 90 app

# Use a specific profile
iamctl role-list --profile staging ops
```

---

#### `policy-list` — List IAM Managed Policies

Search IAM managed policies whose names contain a case-insensitive substring.

```bash
iamctl policy-list [options] <query>
```

**Options:**
- `--output <format>`: Output format — `list` or `json` (default: `list`)
- `--profile <name>`: AWS profile to use
- `--scope <scope>`: Policy scope — `all`, `aws`, or `local` (default: `all`)
- `--description-contains <text>`: Keep only matches whose description contains text
- `--description-not-contains <text>`: Exclude matches whose description contains text

**Examples:**

```bash
# List all managed policies containing "read"
iamctl policy-list read

# Search only customer-managed policies
iamctl policy-list --scope local app

# Keep only policies whose description contains "readonly"
iamctl policy-list --description-contains readonly read

# Exclude policies whose description contains "deprecated"
iamctl policy-list --description-not-contains deprecated read

# JSON output using a specific profile
iamctl policy-list --output json --profile staging ops
```

---

#### `pb-check-cf` — Check a CloudFormation Template Against a Permission Boundary

Parse a CloudFormation template, extract IAM roles and standalone IAM policies, fetch their managed policies from AWS, and evaluate all actions against the permission boundary.

Supported resource types:
- `AWS::IAM::Role` (managed + inline policies)
- `AWS::IAM::Policy` (standalone policy)
- `AWS::IAM::ManagedPolicy` (standalone managed policy)

The permission boundary is resolved in order:
1. `--pb` flag (explicit local file)
2. `PermissionsBoundary` property from roles in the template (fetched from AWS by ARN)

For standalone policies (`AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`), `--pb` is required since they don't have a `PermissionsBoundary` property.

CloudFormation intrinsic functions (`Ref`, `Fn::Join`, etc.) in ARN values cannot be resolved without stack parameters and are silently skipped.

```bash
iamctl pb-check-cf [options] <template-file>
```

**Options:**
- `--pb <file>`: Path to permission boundary file (if omitted, resolves from the template's `PermissionsBoundary` property; **required** for standalone policies)
- `--output <format>`: Output format — `list` or `json` (default: `list`)
- `--profile <name>`: AWS profile to use
- `--resource <logical-id>`: Check only a specific IAM resource by its logical ID (role or policy)

**Examples:**

```bash
# Check all IAM roles and policies in a CloudFormation template
iamctl pb-check-cf template.yaml

# Override the permission boundary with a local file
iamctl pb-check-cf --pb boundary.json template.yaml

# Check a specific role resource by logical ID
iamctl pb-check-cf --resource LambdaRole template.yaml

# Check a standalone policy resource
iamctl pb-check-cf --pb boundary.json --resource MyManagedPolicy template.yaml

# Use a specific AWS profile and JSON output
iamctl pb-check-cf --profile staging --output json template.yaml
```

**What gets analyzed:**
- **IAM Roles**: Managed policy ARNs are fetched from AWS; inline policies are parsed from YAML
- **Standalone policies** (`AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`): `PolicyDocument` is parsed directly from YAML
- **Intrinsic function ARNs**: Skipped (e.g. `Fn::Join`, `Ref` in ARN values)

**Exit Codes:**
- `0`: All actions in all resources are allowed
- `1`: One or more actions are blocked in any resource

---

#### `pb-diff` — Compare Permission Boundaries

Compare a policy's actions against two permission boundaries to see what access would be gained or lost when switching from one boundary to another.

```bash
iamctl pb-diff --pb <old-boundary> --pb-new <new-boundary> <policy-file>
```

**Options:**
- `--pb <file>` **(required)**: Path to the old (current) permission boundary file
- `--pb-new <file>` **(required)**: Path to the new permission boundary to compare against
- `--output <format>`: Output format — `list` or `json` (default: `list`)

**Examples:**

```bash
# Compare boundaries and see what changes
iamctl pb-diff --pb old-pb.json --pb-new new-pb.json policy.json

# JSON output for CI integration
iamctl pb-diff --pb old-pb.json --pb-new new-pb.json --output json policy.json
```

**Exit Codes:**
- `0`: No access is lost
- `1`: One or more actions would lose access

---

#### `policy-from-role-usage` — Generate Policy from Actual Usage

Analyze a role's service last accessed data (at ACTION_LEVEL granularity) and generate a brand-new least-privilege policy containing only the actions the role has actually used.

AWS IAM tracks action-level usage for up to 400 days. The command displays the tracking period so you know what time range is covered.

```bash
iamctl policy-from-role-usage [options] <role-name>
```

**Options:**
- `--profile <name>`: AWS profile to use
- `-q, --quiet`: Suppress informational output, print only the policy JSON (useful for scripts)

**Examples:**

```bash
# Generate a policy from a role's usage
iamctl policy-from-role-usage my-role

# Use a specific AWS profile
iamctl policy-from-role-usage --profile staging my-role

# Quiet mode for piping into a file
iamctl policy-from-role-usage -q my-role > minimal-policy.json
```

---

#### `shrink-role-policies` — Shrink a Role's Policies

Fetch all managed policies attached to a role and remove unused actions based on service last accessed data. The output is a single consolidated policy preserving the original structure (Sids, Resources, Conditions) with only unused Allow actions removed.

Deny statements, NotAction statements, and Conditions are preserved as-is by default.
Use `--strict` to expand wildcard actions to exact observed actions and deduplicate equivalent statements while preserving targeted resources.

```bash
iamctl shrink-role-policies [options] <role-name>
```

**Options:**
- `--profile <name>`: AWS profile to use
- `-q, --quiet`: Suppress informational output, print only the policy JSON (useful for scripts)
- `--ignore-deny`: Omit Deny statements from the output policy
- `--strict`: Expand wildcard actions to exact observed actions and deduplicate equivalent statements while preserving targeted resources

**Examples:**

```bash
# Shrink a role's policies to only used actions
iamctl shrink-role-policies my-role

# Use a specific AWS profile
iamctl shrink-role-policies --profile staging my-role

# Quiet mode for piping into a file
iamctl shrink-role-policies -q my-role > shrunk-policy.json

# Omit Deny statements from the output
iamctl shrink-role-policies --ignore-deny my-role

# Expand wildcards to exact observed actions and deduplicate equivalent statements while preserving targeted resources
iamctl shrink-role-policies --strict my-role
```

## Permission Boundary Format

The tool supports multiple permission boundary formats with different evaluation behaviors:

### Full Policy Formats (Recommended)

These formats use **proper IAM evaluation logic** including Allow statements, Deny statements, and NotAction handling. Use these for accurate permission boundary validation.

#### AWS IAM GetPolicyVersion Format
Direct output from `aws iam get-policy-version`:

```json
{
  "PolicyVersion": {
    "Document": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        },
        {
          "Effect": "Deny",
          "Resource": "*",
          "NotAction": [
            "ec2:Describe*",
            "ec2:CreateTags",
            "kms:Decrypt"
          ]
        }
      ]
    }
  }
}
```

#### Standard Policy Document Format
Standard IAM policy document:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Resource": "*",
      "NotAction": ["ec2:Describe*", "kms:*"]
    }
  ]
}
```

**Evaluation Logic:**
1. Check Allow statements — if action matches, it's potentially allowed
2. Check Deny statements — if action matches, it's explicitly denied
3. Special handling for NotAction in Deny statements — denies everything EXCEPT listed patterns
4. Explicit Deny always wins over Allow

### Simple Pattern Formats

These formats use **basic wildcard pattern matching only**. Use these for simple allowlists where you just want to check if an action matches any pattern.

#### Simple Pattern Array
```json
[
  "ec2:Describe*",
  "ec2:CreateTags",
  "kms:*"
]
```

#### Plain Text (one pattern per line)
```
ec2:Describe*
ec2:CreateTags
kms:*
# Comments are supported
```

**Evaluation Logic:**
- Actions matching any pattern → Allowed
- Actions not matching any pattern → Blocked
- No support for Allow/Deny/NotAction logic

### Which Format Should I Use?

- **Use full policy formats** when validating against real AWS permission boundaries.
- **Use simple formats** for quick checks against a simple allowlist of patterns.

## Output Formats

### List Format (Default)

```
🟢  Allowed actions:
    ec2:CreateFleet
    ec2:DescribeInstances
    ec2:DescribeSubnets

🔴  Blocked actions (not allowed by permission boundary):
    ec2:AttachNetworkInterface
    eks:DescribeCluster

Summary: 28 allowed, 15 blocked
```

### JSON Format

```json
{
  "evaluation_method": "Full IAM policy evaluation",
  "allowed": [
    "ec2:CreateFleet",
    "ec2:DescribeInstances"
  ],
  "blocked": [
    "ec2:AttachNetworkInterface",
    "eks:DescribeCluster"
  ],
  "skipped_deny": [],
  "not_action_statements": [],
  "warnings": [],
  "summary": {
    "allowed": 28,
    "blocked": 15,
    "skipped_deny": 0,
    "not_action_statements": 0
  }
}
```

### Table Format

```
     ACTION                                                     STATUS
---------------------------------------------------------------------------
🟢  ec2:CreateFleet                                            ALLOWED
🟢  ec2:DescribeInstances                                      ALLOWED
🔴  ec2:AttachNetworkInterface                                 BLOCKED
🔴  eks:DescribeCluster                                        BLOCKED

Summary: 28 allowed, 15 blocked, 0 skipped (denied by policy), 0 NotAction statement(s)
```

## Contributing

Contributions welcome! Please open an issue or submit a pull request.