## iamctl diff

Compare policy actions against two permission boundaries to show what changes

### Synopsis

Loads two permission boundaries (--pb and --pb-new) and reports which Allow actions
in the given policy would gain or lose access when switching from the old to the new boundary.

```
iamctl diff <policy-file> [flags]
```

### Examples

```
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json --output json policy.json
```

### Options

```
  -h, --help            help for diff
      --output string   Output format: list or json (default "list")
      --pb string       Path to the permission boundary file (JSON or text format), or '-' for stdin
      --pb-new string   Path to the new permission boundary to compare against (required)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

