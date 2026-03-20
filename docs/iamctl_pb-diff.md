## iamctl pb-diff

Compare policy actions against two permission boundaries

### Synopsis

Loads two permission boundaries (--pb and --pb-new) and reports which Allow actions
would gain or lose access when switching from the old to the new boundary.

Actions can come from a local policy file (positional argument or stdin via '-')
or be fetched live from AWS by specifying an IAM role with --role.

```
iamctl pb-diff [policy-file] [flags]
```

### Examples

```
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json --output json policy.json
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json --role my-role
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json --role my-role --profile staging
```

### Options

```
  -h, --help             help for pb-diff
      --output string    Output format: list or json (default "list")
      --pb string        Path to the old permission boundary file (JSON or text format), or '-' for stdin
      --pb-new string    Path to the new permission boundary to compare against (required)
      --profile string   AWS profile to use when fetching role policies
      --role string      IAM role name to fetch managed policies from AWS (mutually exclusive with policy file argument)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

