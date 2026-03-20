## iamctl merge-role-policies

Merge all managed policies attached to a role into a single unified policy JSON

```
iamctl merge-role-policies <role-name> [flags]
```

### Examples

```
  iamctl merge-role-policies my-role
  iamctl merge-role-policies --quiet my-role
  iamctl merge-role-policies --ignore-deny my-role
  iamctl merge-role-policies --strict my-role
  iamctl merge-role-policies --profile staging my-role
```

### Options

```
  -h, --help             help for merge-role-policies
      --ignore-deny      Omit Deny statements from the output policy
      --profile string   AWS profile to use (defaults to current AWS_PROFILE / default)
  -q, --quiet            Suppress informational output, print only the policy JSON
      --strict           Compact equivalent statements by normalizing and merging actions with identical Effect/Resource/Condition
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

