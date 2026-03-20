## iamctl pb-check-role

Check an IAM role's actions (managed and inline policies) against a permission boundary

```
iamctl pb-check-role <role-name> [flags]
```

### Examples

```
  iamctl pb-check-role my-role
  iamctl pb-check-role --pb boundary.json --output json my-role
  iamctl pb-check-role --profile staging my-role
```

### Options

```
  -h, --help             help for pb-check-role
      --output string    Output format: list or json (default "list")
      --pb string        Path to the permission boundary file (if omitted, fetches the role's own PB from AWS)
      --profile string   AWS profile to use (defaults to current AWS_PROFILE / default)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

