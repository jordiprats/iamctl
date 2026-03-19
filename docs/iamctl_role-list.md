## iamctl role-list

List IAM roles whose names contain a string

```
iamctl role-list <query> [flags]
```

### Examples

```
  iamctl role-list app
  iamctl role-list --active-within-days 90 app
  iamctl role-list --output json read
  iamctl role-list --profile staging ops
```

### Options

```
      --active-within-days int   Filter matches to roles active within the last N days (0 disables filter)
  -h, --help                     help for role-list
      --output string            Output format: list or json (default "list")
      --profile string           AWS profile to use (defaults to current AWS_PROFILE / default)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

