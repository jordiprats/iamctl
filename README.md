# iamctl — IAM Inspection and Permission-Boundary Analysis

A command-line tool for inspecting **AWS IAM roles and policies**, validating access against **permission boundary policies**, generating least-privilege policies from actual role usage, and more.

## Overview

This tool allows you to:

1. **Permission Boundary Check** (`pb-check`): Unified command to check actions, policy files, IAM roles, or CloudFormation templates against a permission boundary — replaces the old `pb-check-action`, `pb-check-policy`, `pb-check-role`, and `pb-check-cf` commands (all old names still work as aliases).
2. **Describe Role** (`describe-role`): Show role summary details, switch role link, managed policies, and inline policy JSON.
3. **Describe Policy** (`describe-policy`): Show managed policy metadata and its JSON document.
4. **Role List** (`role-list`): List IAM roles whose name contains a given string, with optional last-activity filtering.
5. **Policy List** (`policy-list`): List IAM managed policies whose name contains a given string, with optional description filters.
6. **Permission Boundary Diff** (`pb-diff`): Compare a policy against two permission boundaries to see what access would be gained or lost.
7. **Policy from Role Usage** (`policy-from-role-usage`): Generate a least-privilege policy based on a role's actual usage (service last accessed data).
8. **Shrink Role Policies** (`shrink-role-policies`): Take a role's existing attached policies and remove unused actions based on actual usage.
9. **Merge Policies** (`merge-policies`): Merge policies from a role or CloudFormation template into a single unified policy JSON.

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

#### `pb-check` — Unified Permission Boundary Check

Check actions, policy files, IAM roles, or CloudFormation templates against a permission boundary. This single command replaces the old `pb-check-action`, `pb-check-policy`, `pb-check-role`, and `pb-check-cf` commands — all old names still work as aliases.

```bash
# Check specific actions
iamctl pb-check --action <action> [--action <action>...] --pb <boundary-file>

# Check a policy file
iamctl pb-check --pb <boundary-file> [policy-file]

# Check an IAM role
iamctl pb-check --role <role-name> [--pb <boundary-file>]

# Check a CloudFormation template
iamctl pb-check --cf-template <template-file> [--pb <boundary-file>]
```

Exactly one source is required: `--action`, a policy file (positional arg), `--role`, or `--cf-template`.

**Options:**
- `--pb <file>`: Path to permission boundary file (JSON or text format), or `-` for stdin. Required for action and policy checks; optional for role checks (auto-fetches the role's own PB) and CF checks (resolves from template).
- `--action <action>`: Action(s) to check directly (can be repeated)
- `--role <name>`: AWS IAM role name to check (fetches all managed + inline policies)
- `--cf-template <file>`: Path to a CloudFormation template file
- `--output <format>`: Output format — `list`, `json`, `table`, or `sarif` (default: `list`; `sarif` only with `--cf-template`)
- `--profile <name>`: AWS profile to use
- `--policy-file <file>`: Additional policy file to include (can be repeated; only with policy-file mode)
- `--managed-policy <arn>`: ARN of a managed policy to fetch from AWS (can be repeated; only with policy-file mode)
- `--resource <logical-id>`: Logical ID of a specific IAM resource (only with `--cf-template`)

**Examples:**

```bash
# Check if specific actions are allowed
iamctl pb-check --action ec2:RunInstances --pb pb.json
iamctl pb-check --action s3:PutObject --action s3:GetObject --pb pb.json

# Analyze a local policy file
iamctl pb-check --pb pb.json policy.json
iamctl pb-check --pb pb.json --output json policy.json
iamctl pb-check --pb pb.json --output table policy.json

# Check an AWS managed policy by ARN
iamctl pb-check --pb pb.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess

# Combine a local file with managed policies
iamctl pb-check --pb pb.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess policy.json

# Check a role (auto-fetches its permission boundary)
iamctl pb-check --role my-role
iamctl pb-check --role my-role --pb boundary.json --output json
iamctl pb-check --role my-role --profile staging

# Check a CloudFormation template
iamctl pb-check --cf-template template.yaml
iamctl pb-check --cf-template template.yaml --resource LambdaRole
iamctl pb-check --cf-template template.yaml --pb boundary.json --output sarif

# Legacy aliases still work:
iamctl check-action --pb pb.json ec2:RunInstances
iamctl check-policy --pb pb.json policy.json
iamctl check-role my-role
iamctl check-cf template.yaml
```

**Backward Compatibility:**
When invoked as `check-action`/`pb-check-action`/`ca`, positional arguments are treated as action names. When invoked as `check-role`/`pb-check-role`/`cr`, the first positional argument is the role name. When invoked as `check-cf`/`pb-check-cf`/`ccf`, the first positional argument is the template file.

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked/denied

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

#### SARIF Output (CloudFormation mode)

When using `--cf-template` with `--output sarif`, the command produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) document with one result per blocked action. Upload to GitHub Code Scanning to get inline PR annotations:

```yaml
- run: iamctl pb-check --cf-template template.yaml --pb boundary.json --output sarif > results.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

SARIF rules emitted:
| Rule | Level | Meaning |
|------|-------|---------|
| `PB001` | `error` | Action blocked by permission boundary |
| `PB002` | `warning` | Resource has wildcard actions requiring manual review |
| `PB003` | `warning` | Resource has a `NotAction` statement requiring manual review |

---

#### `pb-diff` — Compare Permission Boundaries

Compare a policy's actions against two permission boundaries to see what access would be gained or lost when switching from one boundary to another.

Policy source — specify exactly one:
- A local JSON policy file (positional argument, or `-` for stdin)
- `--role <name>` to fetch the role's attached managed policies live from AWS

```bash
iamctl pb-diff --pb <old-boundary> --pb-new <new-boundary> [policy-file]
iamctl pb-diff --pb <old-boundary> --pb-new <new-boundary> --role <role-name>
```

**Options:**
- `--pb <file>` **(required)**: Path to the old (current) permission boundary file
- `--pb-new <file>` **(required)**: Path to the new permission boundary to compare against
- `--role <name>`: IAM role name — fetch its managed policies from AWS instead of using a local file
- `--profile <name>`: AWS profile to use when `--role` is specified
- `--output <format>`: Output format — `list` or `json` (default: `list`)

**Examples:**

```bash
# Compare boundaries against a local policy file
iamctl pb-diff --pb old-pb.json --pb-new new-pb.json policy.json

# Compare boundaries against a live IAM role's attached policies
iamctl pb-diff --pb old-pb.json --pb-new new-pb.json --role my-role

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

---

#### `merge-policies` — Merge Policies

Merge IAM policies from a role or CloudFormation template into a single unified policy JSON. Useful for inspecting the combined effective policy or as input to other tools.

Sources (exactly one required):
- `--role <name>`: Fetch managed policies from a live AWS IAM role
- `--cf-template <file>`: Parse a CloudFormation template and extract policies

Deny statements, NotAction statements, and Conditions are preserved as-is by default.
Use `--strict` to deduplicate and normalize equivalent statements.

```bash
iamctl merge-policies --role <role-name> [options]
iamctl merge-policies --cf-template <template-file> [options]
```

**Options:**
- `--role <name>`: AWS IAM role name to fetch policies from
- `--cf-template <file>`: Path to a CloudFormation template file
- `--resource <logical-id>`: Logical ID of a specific IAM resource (only with `--cf-template`)
- `--profile <name>`: AWS profile to use
- `-q, --quiet`: Suppress informational output, print only the policy JSON (useful for scripts)
- `--ignore-deny`: Omit Deny statements from the output policy
- `--strict`: Compact equivalent statements by normalizing and merging actions with identical Effect/Resource/Condition

**Aliases:** `mp`, `merge-role-policies`, `mrp`, `merge-cf-policies`, `mcp`

**Examples:**

```bash
# Merge all managed policies for a role
iamctl merge-policies --role my-role

# Quiet mode for piping into a file
iamctl merge-policies --role my-role -q > merged-policy.json

# Merge from a CloudFormation template
iamctl merge-policies --cf-template template.yaml
iamctl merge-policies --cf-template template.yaml --resource LambdaRole

# Omit Deny statements
iamctl merge-policies --role my-role --ignore-deny

# Compact and deduplicate equivalent statements
iamctl merge-policies --role my-role --strict

# Use the merged output as input to pb-check
iamctl merge-policies --role my-role -q | iamctl pb-check --pb boundary.json -
```

**Exit Codes:**
- `0`: Merged policy successfully printed
- `1`: Error (role not found, no policies attached, AWS error)

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