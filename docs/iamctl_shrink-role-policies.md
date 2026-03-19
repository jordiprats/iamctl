## iamctl shrink-role-policies

Generate a minimal policy for a role by removing unused actions from its attached policies

### Synopsis

Fetches all managed policies attached to the given role, then uses service last accessed
data (at ACTION_LEVEL granularity) to identify which actions are actually being used.

Outputs a single consolidated policy containing only the actions the role has really used.
Deny statements, NotAction statements, Conditions, Resources, and Sids are preserved as-is.

```
iamctl shrink-role-policies <role-name> [flags]
```

### Examples

```
  iamctl shrink-role-policies my-role
  iamctl shrink-role-policies --profile staging my-role
```

### Options

```
  -h, --help             help for shrink-role-policies
      --profile string   AWS profile to use
  -q, --quiet            Suppress informational output, print only the policy JSON
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

