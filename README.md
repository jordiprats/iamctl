# iamctl — AWS IAM Swiss Army Knife

A command-line tool for validating **AWS IAM actions** against **permission boundary policies**, generating least-privilege policies from actual role usage, and more.

## Overview

This tool allows you to:

1. **Single Action Check** (`check-action`): Verify if one or more AWS actions are allowed by your permission boundary.
2. **Policy Validation** (`check-policy`): Analyze all actions in a local policy file or AWS managed policies and identify which are allowed vs blocked.
3. **Role Check** (`check-role`): Fetch all managed policies attached to an **IAM role** and evaluate them against the permission boundary.
4. **CloudFormation Check** (`check-cf`): Analyze IAM roles and policies from a **CloudFormation template** against the permission boundary.
5. **Diff** (`diff`): Compare a policy against two permission boundaries to see what access would be gained or lost.
6. **Policy from Role Usage** (`policy-from-role-usage`): Generate a least-privilege policy based on a role's actual usage (service last accessed data).
7. **Shrink Role Policies** (`shrink-role-policies`): Take a role's existing attached policies and remove unused actions based on actual usage.

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

#### `check-action` — Check Actions

Verify if one or more AWS actions are allowed by your permission boundary.

```bash
iamctl check-action --pb <boundary-file> <action> [action...]
```

**Options:**
- `--pb <file>` **(required)**: Path to permission boundary file (JSON or text format), or `-` for stdin

**Examples:**

```bash
# Check if ec2:RunInstances is allowed
iamctl check-action --pb pb.json ec2:RunInstances

# Check multiple actions at once
iamctl check-action --pb pb.json s3:PutObject s3:GetObject ec2:DescribeInstances

# Read boundary from stdin
aws iam get-policy-version ... | iamctl check-action --pb - ec2:RunInstances
```

**Exit Codes:**
- `0`: All actions are allowed by the permission boundary
- `1`: One or more actions are denied

---

#### `check-policy` — Validate IAM Policy

Analyze all actions in a local policy file and/or AWS managed policies, and determine which are allowed or blocked by the permission boundary.

```bash
iamctl check-policy --pb <boundary-file> [policy-file] [options]
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
iamctl check-policy --pb pb.json policy.json

# JSON output for programmatic use
iamctl check-policy --pb pb.json --output json policy.json

# Table format for easy reading
iamctl check-policy --pb pb.json --output table policy.json

# Check an AWS managed policy by ARN
iamctl check-policy --pb pb.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess

# Combine multiple managed policies
iamctl check-policy --pb pb.json \
  --managed-policy arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \
  --managed-policy arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess

# Combine a local file with managed policies
iamctl check-policy --pb pb.json \
  --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess \
  custom-policy.json

# Read policy from stdin
cat policy.json | iamctl check-policy --pb pb.json -
```

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked

---

#### `check-role` — Check an IAM Role

Fetch all managed policies attached to an IAM role and evaluate them against the permission boundary. If `--pb` is omitted, the tool automatically fetches the role's own permission boundary from AWS.

```bash
iamctl check-role [options] <role-name>
```

**Options:**
- `--pb <file>`: Path to permission boundary file (if omitted, fetches the role's own PB from AWS)
- `--output <format>`: Output format — `list` or `json` (default: `list`)
- `--profile <name>`: AWS profile to use

**Examples:**

```bash
# Check a role (auto-fetches its permission boundary)
iamctl check-role my-role

# Use a specific boundary file instead
iamctl check-role --pb boundary.json my-role

# JSON output with a specific AWS profile
iamctl check-role --profile staging --output json my-role
```

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked

---

#### `check-cf` — Check a CloudFormation Template

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
iamctl check-cf [options] <template-file>
```

**Options:**
- `--pb <file>`: Path to permission boundary file (if omitted, resolves from the template's `PermissionsBoundary` property; **required** for standalone policies)
- `--output <format>`: Output format — `list` or `json` (default: `list`)
- `--profile <name>`: AWS profile to use
- `--resource <logical-id>`: Check only a specific IAM resource by its logical ID (role or policy)

**Examples:**

```bash
# Check all IAM roles and policies in a CloudFormation template
iamctl check-cf template.yaml

# Override the permission boundary with a local file
iamctl check-cf --pb boundary.json template.yaml

# Check a specific role resource by logical ID
iamctl check-cf --resource LambdaRole template.yaml

# Check a standalone policy resource
iamctl check-cf --pb boundary.json --resource MyManagedPolicy template.yaml

# Use a specific AWS profile and JSON output
iamctl check-cf --profile staging --output json template.yaml
```

**What gets analyzed:**
- **IAM Roles**: Managed policy ARNs are fetched from AWS; inline policies are parsed from YAML
- **Standalone policies** (`AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`): `PolicyDocument` is parsed directly from YAML
- **Intrinsic function ARNs**: Skipped (e.g. `Fn::Join`, `Ref` in ARN values)

**Exit Codes:**
- `0`: All actions in all resources are allowed
- `1`: One or more actions are blocked in any resource

---

#### `diff` — Compare Permission Boundaries

Compare a policy's actions against two permission boundaries to see what access would be gained or lost when switching from one boundary to another.

```bash
iamctl diff --pb <old-boundary> --pb-new <new-boundary> <policy-file>
```

**Options:**
- `--pb <file>` **(required)**: Path to the old (current) permission boundary file
- `--pb-new <file>` **(required)**: Path to the new permission boundary to compare against
- `--output <format>`: Output format — `list` or `json` (default: `list`)

**Examples:**

```bash
# Compare boundaries and see what changes
iamctl diff --pb old-pb.json --pb-new new-pb.json policy.json

# JSON output for CI integration
iamctl diff --pb old-pb.json --pb-new new-pb.json --output json policy.json
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

Deny statements, NotAction statements, and Conditions are preserved as-is.

```bash
iamctl shrink-role-policies [options] <role-name>
```

**Options:**
- `--profile <name>`: AWS profile to use
- `-q, --quiet`: Suppress informational output, print only the policy JSON (useful for scripts)

**Examples:**

```bash
# Shrink a role's policies to only used actions
iamctl shrink-role-policies my-role

# Use a specific AWS profile
iamctl shrink-role-policies --profile staging my-role

# Quiet mode for piping into a file
iamctl shrink-role-policies -q my-role > shrunk-policy.json
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