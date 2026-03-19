## iamctl check-policy

Check which actions in a policy are allowed or blocked by the permission boundary

```
iamctl check-policy [policy-file] [flags]
```

### Examples

```
  iamctl check-policy --pb boundary.json policy.json
  iamctl check-policy --pb boundary.json --policy-file extra.json policy.json
  iamctl check-policy --pb boundary.json --policy-file a.json --policy-file b.json
  iamctl check-policy --pb boundary.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess
  iamctl check-policy --pb boundary.json --output json policy.json
  iamctl check-policy --pb boundary.json --output table policy.json
  cat policy.json | iamctl check-policy --pb boundary.json -
```

### Options

```
  -h, --help                     help for check-policy
      --managed-policy strings   ARN of a managed policy to fetch from AWS (can be specified multiple times)
      --output string            Output format: list, json, or table (default "list")
      --pb string                Path to the permission boundary file (JSON or text format), or '-' for stdin
      --policy-file strings      Path to an additional policy file to include (can be specified multiple times)
      --profile string           AWS profile to use when fetching managed policies
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

