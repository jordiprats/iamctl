## iamctl describe-policy

Describe a managed policy and show its JSON document

```
iamctl describe-policy <policy-arn> [flags]
```

### Examples

```
  iamctl describe-policy arn:aws:iam::aws:policy/ReadOnlyAccess
  iamctl describe-policy --json-policy arn:aws:iam::123456789012:policy/MyPolicy
  iamctl describe-policy --profile staging arn:aws:iam::123456789012:policy/MyPolicy
```

### Options

```
  -h, --help             help for describe-policy
      --json-policy      Print only the policy JSON document
      --profile string   AWS profile to use (defaults to current AWS_PROFILE / default)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

