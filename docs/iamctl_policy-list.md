## iamctl policy-list

List IAM managed policies whose names contain a string

```
iamctl policy-list <query> [flags]
```

### Examples

```
  iamctl policy-list read
  iamctl policy-list --scope local app
  iamctl policy-list --description-contains readonly read
  iamctl policy-list --description-not-contains deprecated read
  iamctl policy-list --output json --profile staging ops
```

### Options

```
      --description-contains string       Filter matches to policies whose description contains this string
      --description-not-contains string   Filter matches to policies whose description does not contain this string
  -h, --help                              help for policy-list
      --output string                     Output format: list or json (default "list")
      --profile string                    AWS profile to use (defaults to current AWS_PROFILE / default)
      --scope string                      Policy scope: all, aws, or local (default "all")
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

