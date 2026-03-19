## iamctl

AWS IAM Swiss Army Knife

### Synopsis

Validate AWS IAM actions and policies against a permission boundary definition, generate least-privilege policies, and more.

### Options

```
  -h, --help   help for iamctl
```

### SEE ALSO

* [iamctl check-action](iamctl_check-action.md)	 - Check if one or more actions are allowed by the permission boundary
* [iamctl check-cf](iamctl_check-cf.md)	 - Parse a CloudFormation template and check IAM roles and policies against the permission boundary
* [iamctl check-policy](iamctl_check-policy.md)	 - Check which actions in a policy are allowed or blocked by the permission boundary
* [iamctl check-role](iamctl_check-role.md)	 - Fetch managed policies for an IAM role and check which actions are blocked by the permission boundary
* [iamctl diff](iamctl_diff.md)	 - Compare policy actions against two permission boundaries to show what changes
* [iamctl policy-from-role-usage](iamctl_policy-from-role-usage.md)	 - Generate a least-privilege policy based on a role's actual usage (service last accessed data)
* [iamctl shrink-role-policies](iamctl_shrink-role-policies.md)	 - Generate a minimal policy for a role by removing unused actions from its attached policies

