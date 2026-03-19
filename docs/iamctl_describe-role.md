## iamctl describe-role

Describe an IAM role, including summary, managed policies, and inline policies

```
iamctl describe-role <role-name> [flags]
```

### Examples

```
  iamctl describe-role my-role
  iamctl describe-role --output json my-role
  iamctl describe-role --profile staging my-role
```

### Options

```
  -h, --help             help for describe-role
      --output string    Output format: wide or json (default "wide")
      --profile string   AWS profile to use (defaults to current AWS_PROFILE / default)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

