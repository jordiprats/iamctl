## iamctl check-role

Fetch managed policies for an IAM role and check which actions are blocked by the permission boundary

```
iamctl check-role <role-name> [flags]
```

### Examples

```
  iamctl check-role my-role
  iamctl check-role --pb boundary.json --output json my-role
  iamctl check-role --profile staging my-role
```

### Options

```
  -h, --help             help for check-role
      --output string    Output format: list or json (default "list")
      --pb string        Path to the permission boundary file (if omitted, fetches the role's own PB from AWS)
      --profile string   AWS profile to use (defaults to current AWS_PROFILE / default)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

