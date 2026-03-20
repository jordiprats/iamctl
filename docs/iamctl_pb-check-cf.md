## iamctl pb-check-cf

Check CloudFormation IAM resources against a permission boundary

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
iamctl pb-check-cf <template-file> [flags]
```

### Examples

```
  iamctl pb-check-cf template.yaml
	iamctl pb-check-cf --pb boundary.json template.yaml
	iamctl pb-check-cf --resource LambdaRole template.yaml
	iamctl pb-check-cf --profile staging --output json template.yaml
	iamctl pb-check-cf --pb boundary.json --output sarif template.yaml > results.sarif
	iamctl pb-check-cf --pb boundary.json --resource MyPolicy template.yaml
```

### Options

```
  -h, --help              help for pb-check-cf
      --output string     Output format: list, json, or sarif (default "list")
      --pb string         Path to the permission boundary file (if omitted, resolves from template)
      --profile string    AWS profile to use
      --resource string   Logical ID of a specific IAM resource to check (role or policy)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

