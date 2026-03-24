## iamctl pb-check

Check actions, policies, roles, or CloudFormation templates against a permission boundary

### Synopsis

Evaluate IAM actions against a permission boundary.

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
  is treated as the CloudFormation template file.

```
iamctl pb-check [policy-file] [flags]
```

### Examples

```
  # Check specific actions
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
  iamctl pb-check --cf-template template.yaml --pb boundary.json --output sarif
```

### Options

```
      --action strings           Action(s) to check directly (can be repeated)
      --cf-template string       Path to a CloudFormation template file
  -h, --help                     help for pb-check
      --managed-policy strings   ARN of a managed policy to fetch from AWS (can be repeated)
      --output string            Output format: list, json, table, or sarif (sarif only with --cf-template) (default "list")
      --pb string                Path to the permission boundary file (JSON or text format), or '-' for stdin
      --policy-file strings      Path to an additional policy file (can be repeated)
      --profile string           AWS profile to use
      --resource string          Logical ID of a specific IAM resource (only with --cf-template)
      --role string              AWS IAM role name to check
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

