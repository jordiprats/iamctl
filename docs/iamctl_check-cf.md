## iamctl check-cf

Parse a CloudFormation template and check IAM roles and policies against the permission boundary

### Synopsis

Parse a CloudFormation template, extract IAM roles and standalone IAM policies,
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
Inline policies from the Policies property are parsed directly.

```
iamctl check-cf <template-file> [flags]
```

### Examples

```
  iamctl check-cf template.yaml
  iamctl check-cf --pb boundary.json template.yaml
  iamctl check-cf --resource LambdaRole template.yaml
  iamctl check-cf --profile staging --output json template.yaml
  iamctl check-cf --pb boundary.json --resource MyPolicy template.yaml
```

### Options

```
  -h, --help              help for check-cf
      --output string     Output format: list or json (default "list")
      --pb string         Path to the permission boundary file (if omitted, resolves from template)
      --profile string    AWS profile to use
      --resource string   Logical ID of a specific IAM resource to check (role or policy)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

