# Entra org directory: org attributes, dynamic groups, `$filter`, `$expand=manager`, claims mapping

Status: implemented. Extends [`02-graph-design.md`](02-graph-design.md); Entra mode only, so the
navikt-compatible routes (contract C1–C9) are untouched.

## 1. Why

The IAM project models its org chart on Entra:

- **Hierarchy:** the `manager` relationship.
- **Org code:** a stable code such as `DEPT001` in `extensionAttribute1`, separate from the
  `department` display name.
- **Department groups:** named by a convention such as `GRP_DEPT_<code>_<name>`, with
  membership from a dynamic rule like `(user.extensionAttribute1 -eq "DEPT001")`. An HR transfer
  then moves people between groups without manual edits.

Before this change the mock could not load such a fixture at all: strict decoding rejected
`department` and `extensionAttribute1`. Groups were static, and `$filter` and `$expand` were
refused. Everything below makes that scenario reachable through the same Graph calls and token
claims as production.

## 2. Config

All fields are optional and additive. A config written before this change still parses.

| Field | Effect |
|---|---|
| `user.department`, `companyName`, `employeeId` | Graph user properties (`$select`-only, §3); rule and claim sources |
| `user.onPremisesExtensionAttributes.extensionAttribute1`–`3` | the org-code slots. **Only 1–3 are supported.** Entra has 15, but `extensionAttribute4`+ is rejected at parse time, so a fixture cannot silently carry data the mock ignores |
| `user.manager` | a username, **object ID or UPN** in the same tenant; stored as the username |
| `tenant.groups[].membershipRule` | makes the group **dynamic** (§4) |
| `apps[].claims[]` | `{"name": "<claim>", "source": "user.<attribute>"}`: claims mapping (§6) |

```json
{
  "tenants": [{ "tid": "…", "groups": [
    { "name": "GRP_DEPT_DEPT001_HRTeam", "membershipRule": "(user.extensionAttribute1 -eq \"DEPT001\")" }
  ]}],
  "apps": [{ "clientId": "iam", "claims": [{ "name": "org_code", "source": "user.extensionAttribute1" }] }],
  "users": [{ "username": "hana", "tid": "…", "department": "HR", "manager": "boss@corp.example",
              "onPremisesExtensionAttributes": { "extensionAttribute1": "DEPT001" } }]
}
```

The shipped `entra-demo.json` has a fourth tenant, "Org Chart (demo)", that exercises all of it.

## 3. Graph user and group properties

**User.** `department`, `companyName`, `employeeId` and `onPremisesExtensionAttributes` (an object
with the three supported keys, nulls when unset) are **`$select`-only**, as in Graph v1.0. A default
`/me` or `/users` body is byte-for-byte what it was before. The properties are still filterable
(§5).

**Group.** Every group now carries `groupTypes`, `membershipRule` and
`membershipRuleProcessingState`:
- a dynamic group: `["DynamicMembership"]`, the rule, and `"On"`
- a static group: `[]`, `null`, `null`

Graph returns these by default, so they are in the default set.

## 4. Dynamic groups

### Rule grammar

Implemented in `internal/entra/rule.go`:

```
rule   := "Direct Reports for" "<manager object id>" | or
or     := and ("-or" and)*
and    := unary ("-and" unary)*
unary  := "-not" unary | "(" or ")" | user.<property> <op> <value>
op     := -eq -ne -startsWith -notStartsWith -contains -notContains -in -notIn
value  := "string" | null | true | false | ["string", …]
```

- **Properties:** `department`, `companyName`, `employeeId`, `jobTitle`, `officeLocation`,
  `displayName`, `mail`, `userPrincipalName`, `extensionAttribute1`–`3`, and `accountEnabled`
  (`-eq`/`-ne` with `true`/`false` only).
- **Case:** property names, operators and string values are case-insensitive, as in Entra.
- **Null:** an unset attribute is `null`. `-ne "HR"` and `-notIn` therefore match users without the
  attribute.
- **Direct Reports:** matches users whose manager has that object ID. It is the org-chart rule for
  a "team of X" group.

### Evaluation

- **When:** membership is computed in `Config.normalize`, after managers resolve. Every
  `entra.Store` mutation re-runs `normalize`. So an admin UI edit of a user's
  `extensionAttribute1`, or the deletion of their manager, moves them between groups for the very
  next request. This is the HR-transfer behavior.
- **Effective membership:** `User.MemberGroups()` returns static plus dynamic groups. Every
  consumer reads it, so they always agree:
  - the `groups` claim and its overage count
  - `memberOf` / `transitiveMemberOf`
  - `/groups/{id}/members`
  - `getMemberObjects`
  - `/_entra/groups`
- **No static members:** a user may not list a dynamic group in `groups`. Entra refuses manual
  members on a dynamic group too.

## 5. `$filter` (collections only)

Implemented in `internal/entra/filter.go`:

```
or      := and ("or" and)*
and     := unary ("and" unary)*
unary   := "not" unary | "(" or ")" | startsWith(path, 'lit')
         | path eq|ne lit | path in (lit, …) | path/any(x: x eq lit)
lit     := 'string' ('' escapes a quote) | null | true | false
path    := property ("/" property)*      e.g. onPremisesExtensionAttributes/extensionAttribute1
```

- **Scope:** collections only: `/users`, `/groups`, `memberOf`, `directReports`, `members` and their
  transitive forms.
- **Evaluation:** filters run against the full entity before `$select`, so `$select`-only
  properties are filterable. They run before paging, and `@odata.nextLink` carries `$filter`
  forward.
- **Case:** comparisons are case-insensitive, like directory queries.
- **Errors:** every failure is `400 Request_UnsupportedQuery`. That covers syntax, an unknown
  property, an unsupported operator (`gt`, `endsWith`, …), comparing a whole complex object, and
  `$filter` on a single entity. The emulator refuses rather than ignores, the same stance as the
  rest of the query options.

Useful queries:

```
GET /groups?$filter=startsWith(displayName,'GRP_DEPT_')
GET /groups?$filter=groupTypes/any(c:c eq 'DynamicMembership')
GET /users?$filter=onPremisesExtensionAttributes/extensionAttribute1 eq 'DEPT001'
```

## 6. `$expand=manager`

- **Routes:** only on `/me`, `/users/{id}` and `/users`. Only `manager` is accepted, optionally as
  `manager($select=id,displayName)`. Anything else, or `$expand` on any other route, is
  `400 Request_UnsupportedQuery`.
- **Shape:** the expanded manager carries `@odata.type: "#microsoft.graph.user"` and the default
  property set (or the inner `$select`). It survives the outer `$select`. A user without a manager
  has no `manager` property.

## 7. Org data in tokens: claims mapping

- **Config:** `apps[].claims` emulates an Entra claims-mapping policy. Each entry copies one user
  attribute into a named claim of the **ID token** issued to that `clientId`.
- **Scope:** an app with a `tid` maps only that tenant's users.
- **Sources:** `user.department`, `companyName`, `employeeId`, `jobTitle`, `officeLocation`,
  `extensionAttribute1`–`3`.
- **Validation:** names may not collide with claims Entra mode emits itself (`groups`, `roles`,
  `oid`, …).
- **Empty values:** an empty attribute is omitted, not emitted as `""`.

Mapped claims are **not** added to the access token. Its audience is Graph, and a claims-mapping
policy applies to tokens issued for the app.

**No `manager` claim.** Entra has no source that emits the manager into a token, so the mock does
not invent one. Read it from `/me/manager` or `$expand=manager`.

## 8. Admin UI

- **User drawer:** edits `department`, `companyName`, `employeeId`, `extensionAttribute1`–`3` and
  `emailVerified`. It previously dropped `emailVerified` on save, because `UpdateUser` is a full
  replace. The drawer lists the user's current dynamic groups, and the users table counts them,
  marked "(dynamic)".
- **Tenant drawer:** a "Groups (JSON)" editor round-trips declared group metadata, including
  `membershipRule`. Before this change, saving a tenant silently wiped its declared groups. The
  snapshot exports `configuredOid` beside the derived `oid`, so a round-trip never pins a derived
  ID.

## 9. Divergences from real Entra

| Area | Here | Real Entra |
|---|---|---|
| Extension attributes | 1–3 only | 1–15 |
| Rule evaluation | synchronous on every change | asynchronous, minutes to hours |
| `membershipRuleProcessingState` | always `"On"`; `Paused` not modeled | `On` or `Paused` |
| Rule language | the §4 subset; no `-match`, `-any`/`-all`, device rules, `memberOf` rules | full language |
| Advanced queries | `ConsistencyLevel: eventual` and `$count=true` are not required (and `$count` stays refused) | some filters, e.g. on `onPremisesExtensionAttributes`, require them |
| Naming policy | names are free text; `GRP_DEPT_…` is a convention, not enforced | group naming policy can enforce prefixes |
| `$expand` | `manager` only | many navigation properties |
| Claims mapping | ID token only, fixed source list | policy-driven, broader sources and transformations |

When the IAM project gets a real tenant, check the advanced-query requirement first: a client that
works here without `ConsistencyLevel: eventual` may get a 400 from real Graph.
