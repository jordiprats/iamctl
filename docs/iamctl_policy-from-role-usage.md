## iamctl policy-from-role-usage

Generate a least-privilege policy based on a role's actual usage (service last accessed data)

```
iamctl policy-from-role-usage <role-name> [flags]
```

### Examples

```
  iamctl policy-from-role-usage my-role
  iamctl policy-from-role-usage --profile staging my-role
```

### Options

```
  -h, --help             help for policy-from-role-usage
      --profile string   AWS profile to use
```

### SEE ALSO

* [iamctl](iamctl.md)	 - AWS IAM Swiss Army Knife

