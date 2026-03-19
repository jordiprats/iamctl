## iamctl pb-check-action

Check whether one or more actions are allowed by a permission boundary

```
iamctl pb-check-action <action> [action...] [flags]
```

### Examples

```
  iamctl pb-check-action ec2:RunInstances
  iamctl pb-check-action s3:PutObject s3:GetObject ec2:DescribeInstances
  iamctl pb-check-action --pb boundary.json s3:PutObject
  aws iam get-policy-version ... | iamctl pb-check-action --pb - ec2:RunInstances
```

### Options

```
  -h, --help        help for pb-check-action
      --pb string   Path to the permission boundary file (JSON or text format), or '-' for stdin
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

