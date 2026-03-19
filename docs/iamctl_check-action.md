## iamctl check-action

Check if one or more actions are allowed by the permission boundary

```
iamctl check-action <action> [action...] [flags]
```

### Examples

```
  iamctl check-action ec2:RunInstances
  iamctl check-action s3:PutObject s3:GetObject ec2:DescribeInstances
  iamctl check-action --pb boundary.json s3:PutObject
  aws iam get-policy-version ... | iamctl check-action --pb - ec2:RunInstances
```

### Options

```
  -h, --help        help for check-action
      --pb string   Path to the permission boundary file (JSON or text format), or '-' for stdin
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

