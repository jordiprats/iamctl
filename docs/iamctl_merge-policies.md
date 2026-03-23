## iamctl merge-policies

Merge IAM policies from a role or CloudFormation template into a single unified policy JSON

### Synopsis

Merge all IAM policy statements into a single policy document.

Sources (exactly one required):
  --role <name>            Fetch managed policies from a live AWS IAM role
  --cf-template <file>     Parse a CloudFormation template and extract policies

When using --cf-template, use --resource to target a specific IAM resource by logical ID.
When not specified, all IAM resources in the template are merged together.

Supported CloudFormation resource types:
  - AWS::IAM::Role (managed + inline policies)
  - AWS::IAM::Policy (standalone policy)
  - AWS::IAM::ManagedPolicy (standalone managed policy)

Managed policy ARNs are fetched from AWS. Intrinsic functions (Fn::Join, Ref, Fn::Sub)
in ARN values are resolved automatically using STS GetCallerIdentity.

```
iamctl merge-policies [flags]
```

### Examples

```
  # From a live AWS role
  iamctl merge-policies --role my-role
  iamctl merge-policies --role my-role --quiet
  iamctl merge-policies --role my-role --ignore-deny
  iamctl merge-policies --role my-role --strict --profile staging

  # From a CloudFormation template
  iamctl merge-policies --cf-template template.yaml
  iamctl merge-policies --cf-template template.yaml --resource LambdaRole
  iamctl merge-policies --cf-template template.yaml --ignore-deny --strict
```

### Options

```
      --cf-template string   Path to a CloudFormation template file
  -h, --help                 help for merge-policies
      --ignore-deny          Omit Deny statements from the output policy
      --profile string       AWS profile to use (defaults to current AWS_PROFILE / default)
  -q, --quiet                Suppress informational output, print only the policy JSON
      --resource string      Logical ID of a specific IAM resource to extract (only with --cf-template)
      --role string          AWS IAM role name to fetch policies from
      --strict               Compact equivalent statements by normalizing and merging actions with identical Effect/Resource/Condition
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

