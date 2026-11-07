# Entra org directory: org attributes, dynamic groups, `$filter`, `$expand=manager`, claims mapping

This extends the Graph emulation in [`02-graph-design.md`](02-graph-design.md). It applies to
Entra mode only, so the navikt routes (contract C1 to C9) are unaffected.

## 1. Why

The IAM project models its org chart on Entra. The `manager` relationship is the hierarchy. A
stable org code such as `DEPT001` sits in `extensionAttribute1`, apart from the `department`
display name. Department groups follow a naming convention such as `GRP_DEPT_<code>_<name>`, and a
dynamic rule like `(user.extensionAttribute1 -eq "DEPT001")` sets their members, so an HR transfer
moves people between groups with no manual edit. This document describes how the mock serves that
model through the same Graph calls and token claims as production.

## 2. Config

All fields are optional.

| Field | Effect |
|---|---|
| `user.department`, `companyName`, `employeeId` | Graph user properties (`$select`-only, §3), and sources for rules and claims |
| `user.onPremisesExtensionAttributes.extensionAttribute1` to `3` | The org-code slots. Entra has 15, but `extensionAttribute4` and above fail to parse, so a fixture cannot carry data the mock ignores. |
| `user.manager` | A username, object ID, or UPN in the same tenant, stored as the username. The user cannot be their own manager. Longer cycles are not checked. |
| `tenant.groups[].oid` | Pins the group's object ID. Without it, the ID is derived from the tenant and the name. |
| `tenant.groups[].membershipRule` | Makes the group dynamic (§4) |
| `apps[].claims[]` | `{"name": "<claim>", "source": "user.<attribute>"}`, a claims mapping (§7) |

This excerpt from `entra-demo.json` (the "Org Chart (demo)" tenant) shows each kind:

```json
{
  "tenants": [{ "tid": "44444444-4444-4444-4444-444444444444", "groups": [
    { "name": "GRP_DEPT_DEPT001_HRTeam", "membershipRule": "(user.extensionAttribute1 -eq \"DEPT001\")" },
    { "name": "GRP_REPORTS_CEO", "membershipRule": "Direct Reports for \"44444444-0000-0000-0000-000000000001\"" }
  ]}],
  "apps": [{ "clientId": "iam", "tid": "44444444-4444-4444-4444-444444444444",
             "claims": [{ "name": "org_code", "source": "user.extensionAttribute1" }] }],
  "users": [
    { "username": "ceo", "tid": "44444444-4444-4444-4444-444444444444",
      "oid": "44444444-0000-0000-0000-000000000001", "department": "Executive" },
    { "username": "hrlead", "tid": "44444444-4444-4444-4444-444444444444", "department": "HR",
      "manager": "ceo", "onPremisesExtensionAttributes": { "extensionAttribute1": "DEPT001" } }
  ]
}
```

The demo tenant uses `-eq` rules and a `Direct Reports for` rule. It does not use every operator.

## 3. Graph user and group properties

User `department`, `companyName`, `employeeId`, and `onPremisesExtensionAttributes` are
`$select`-only, as in Graph v1.0. `onPremisesExtensionAttributes` is an object with the three
supported keys, `null` when unset. The default `/me` and `/users` bodies leave them out. `$filter`
can still use them (§5).

Every group carries `groupTypes`, `membershipRule`, and `membershipRuleProcessingState` in its
default property set:

- A dynamic group has `["DynamicMembership"]`, its rule, and `"On"`.
- A static group has `[]`, `null`, and `null`.

## 4. Dynamic groups

### Rule grammar

`internal/entra/rule.go` parses rules:

```
rule   := "Direct Reports for" "<manager object id>" | or
or     := and ("-or" and)*
and    := unary ("-and" unary)*
unary  := "-not" unary | "(" or ")" | user.<property> <op> <value>
op     := -eq -ne -startsWith -notStartsWith -contains -notContains -in -notIn
value  := "string" | null | true | false | ["string", …]
```

- Properties are `department`, `companyName`, `employeeId`, `jobTitle`, `officeLocation`,
  `displayName`, `mail`, `userPrincipalName`, `extensionAttribute1` to `3`, and `accountEnabled`.
- `accountEnabled` takes only `-eq` and `-ne` with `true` or `false`. `null` works only with
  `-eq` and `-ne`. `-in` and `-notIn` take an array. Every other comparison takes a string.
- Property names, operators, and string values are case-insensitive, as in Entra. Strings accept
  backslash escapes.
- An unset attribute is `null`, so `-ne "HR"`, `-notIn`, `-notStartsWith`, and `-notContains`
  match users without the attribute.
- `Direct Reports for` must be the whole rule and takes a GUID. It matches users whose manager has
  that object ID. The parser does not check that the ID exists, so pin the manager's `oid` in
  config, as the demo does for `ceo`. A wrong ID gives an empty group.
- Nesting of `(` and `-not` is capped at 32 levels. A deeper rule fails with "rule nested too
  deeply".
- Device rules, `-match`, `-any`, and `-all` fail to parse.

### Evaluation

`Config.normalize` computes membership after it resolves managers. Every `entra.Store` edit runs
`normalize` again, so an admin edit of a user's `extensionAttribute1`, or deleting their manager,
moves them between groups on the next request.

`User.MemberGroups()` is the user's effective membership: static groups plus dynamic groups,
without duplicates or blanks. Every consumer reads it, so these always agree:

- the `groups` claim and its overage count
- `memberOf` and `transitiveMemberOf`
- `/groups/{id}/members`
- `getMemberObjects` and `getMemberGroups`
- `/_entra/groups`

A user cannot list a dynamic group in `groups`. Entra refuses manual members on a dynamic group
too.

`normalize` also rejects two declared groups in a tenant with the same object ID, and two users in
a tenant with the same object ID, whether configured or derived. The check runs at load and on
every admin edit.

## 5. `$filter` (collections only)

`internal/entra/filter.go` parses `$filter`:

```
or      := and ("or" and)*
and     := unary ("and" unary)*
unary   := "not" unary | "(" or ")" | startsWith(path, 'lit')
         | path eq|ne lit | path in (lit, …) | path/any(x: x eq lit)
lit     := 'string' ('' escapes a quote) | null | true | false
path    := property ("/" property)*      e.g. onPremisesExtensionAttributes/extensionAttribute1
```

- `$filter` works on collections only: `/users`, `/groups`, `memberOf`, `transitiveMemberOf`,
  `directReports`, `members`, and `transitiveMembers`.
- Filters run against the full entity before `$select`, so `$select`-only properties are
  filterable. They run before paging, and `@odata.nextLink` carries `$filter` forward.
- Comparisons are case-insensitive, like directory queries.
- `any()` works only on collection properties (`groupTypes`, `businessPhones`), with `eq` inside.
- Nesting of `(` and `not` is capped at 32 levels. `and` and `or` chains do not count toward it.

Every failure is `400 Request_UnsupportedQuery`: a syntax error, an empty expression, an unknown
property (including a function name such as `endsWith`, which parses as a property), an
unsupported operator such as `gt`, a comparison against a whole complex object, nesting deeper
than 32 levels ("Invalid filter clause: expression nested too deeply."), and `$filter` on a single
entity. The emulator refuses rather than ignores, like the other query options.

Example queries:

```
GET /groups?$filter=startsWith(displayName,'GRP_DEPT_')
GET /groups?$filter=groupTypes/any(c:c eq 'DynamicMembership')
GET /users?$filter=onPremisesExtensionAttributes/extensionAttribute1 eq 'DEPT001'
```

## 6. `$expand=manager`

- `$expand` works only on `/me`, `/users/{id}`, and `/users`, and accepts only `manager`,
  optionally as `manager($select=id,displayName)`. Any other value, any inner option other than
  `$select`, or `$expand` on another route gets `400 Request_UnsupportedQuery`.
- The server checks the inner `$select` before it renders anything, so an unknown property gets
  400 even when no user has a manager.
- The expanded manager carries `@odata.type: "#microsoft.graph.user"` and the default property set,
  or the inner `$select`. It survives the outer `$select`. A user without a manager has no
  `manager` property.
- `$select=manager` with `$expand=manager` is valid on every user, including one without a
  manager. Without `$expand`, it gets 400 for an unknown property.

## 7. Org data in tokens: claims mapping

`apps[].claims` emulates an Entra claims-mapping policy. Each entry copies one user attribute into
a named claim of the ID token issued to that `clientId`.

- An app with a `tid` maps only that tenant's users.
- Sources are `user.department`, `companyName`, `employeeId`, `jobTitle`, `officeLocation`, and
  `extensionAttribute1` to `3`. The `user.` prefix is required and is case-insensitive.
- A claim name cannot repeat within an app and cannot be a claim Entra mode emits itself (`groups`,
  `roles`, `oid`, `appid`, and others). The reserved-name check is case-sensitive.
- An empty attribute is left out, not emitted as `""`.

Mapped claims do not go into the access token. Its audience is Graph, and a claims-mapping policy
applies to tokens issued for the app.

There is no `manager` claim. Entra has no source that puts the manager in a token, so the mock does
not invent one. Read it from `/me/manager` or `$expand=manager`.

## 8. Admin UI

- The user drawer edits `department`, `companyName`, `employeeId`, `extensionAttribute1` to `3`, and
  `emailVerified`. It lists the user's current dynamic groups, and the users table counts them,
  marked "(dynamic)".
- The tenant drawer has a "Groups (JSON)" editor for declared group metadata, including
  `membershipRule` and `oid`. In the admin snapshot, a group's `oid` is its effective object ID and
  `configuredOid` is the configured value, so saving the JSON back never pins a derived ID.

## 9. Divergences from real Entra

| Area | Here | Real Entra |
|---|---|---|
| Extension attributes | 1 to 3 only | 1 to 15 |
| Rule evaluation | Synchronous on every change | Asynchronous, minutes to hours |
| `membershipRuleProcessingState` | Always `"On"`. `Paused` is not modeled. | `On` or `Paused` |
| Rule language | The §4 subset. No `-match`, `-any`, `-all`, device rules, or `memberOf` rules. | Full language |
| Advanced queries | `ConsistencyLevel: eventual` and `$count=true` are not required, and `$count` stays refused | Some filters, for example on `onPremisesExtensionAttributes`, require them (Unverified) |
| Naming policy | Names are free text. `GRP_DEPT_…` is a convention. | A group naming policy can enforce prefixes |
| `$expand` | `manager` only | Many navigation properties |
| Claims mapping | ID token only, fixed source list | Policy-driven, more sources and transformations |

When the IAM project gets a real tenant, check the advanced-query requirement first. A client that
works here without `ConsistencyLevel: eventual` may get a 400 from real Graph.
