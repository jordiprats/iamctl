## iamctl pb-diff

Compare policy actions against two permission boundaries

### Synopsis

Loads two permission boundaries (--pb and --pb-new) and reports which Allow actions
in the given policy would gain or lose access when switching from the old to the new boundary.

```
iamctl pb-diff <policy-file> [flags]
```

### Examples

```
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  iamctl pb-diff --pb old-boundary.json --pb-new new-boundary.json --output json policy.json
```

### Options

```
  -h, --help            help for pb-diff
      --output string   Output format: list or json (default "list")
      --pb string       Path to the permission boundary file (JSON or text format), or '-' for stdin
      --pb-new string   Path to the new permission boundary to compare against (required)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

