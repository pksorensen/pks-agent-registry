# ADR 0001 — Owner permission scopes (push capability + pull scopes)

- Status: Accepted
- Date: 2026-06-20

## Context

The registry's original authorization model was binary at the credential level:

- **Reads** (`requireOwnerAuth`): any owner with a valid password could pull from
  **every** namespace. There was no per-repository read control.
- **Writes** (`requireOwnerWrite`): an owner could push/delete only within its own
  `{owner}` namespace, but **every** owner could push to its own namespace.

This is fine for trusted internal owners, but blocks the customer-distribution use
case. When we hand a customer an owner credential so they can
`docker pull registry.agentics.dk/agentics/pks-agent-marketplace`, that same credential
could also (a) pull any other customer's images and (b) push arbitrary images into its
own namespace. We want a credential that is **pull-only** and **scoped to specific
images**.

## Decision

Add an optional `Permissions` block to each owner:

```go
type Permissions struct {
    Push       bool     `json:"push"`        // may push/delete in OWN namespace
    PullScopes []string `json:"pullScopes"`  // globs over "owner/name" for cross-namespace reads
}
type Owner struct {
    ...
    Permissions *Permissions `json:"permissions,omitempty"`
}
```

Enforcement:

- **`Permissions == nil` ⇒ legacy full access** (push own namespace + pull everything).
  Owners created before this change have no `permissions` key, so they keep working with
  **zero migration** — critical because the live `agentics` owner pushes every release.
- **`Permissions != nil`:**
  - Push/delete in the owner's own namespace requires `Push == true`.
  - A pull of `X/Y` is allowed iff `X == self` (own namespace is always readable) or some
    `PullScopes` glob matches `"X/Y"` via `path.Match` (`*` does not cross `/`), with `*`
    and `*/*` treated as "everything".
- `GET /v2/_catalog` is filtered to repositories the caller may pull.
- The trusted-proxy anonymous-read bypass is unchanged: it grants full reads from the
  configured CIDR and is not scope-checked (operator-controlled internal path).

A customer credential is therefore `{ Push: false, PullScopes: ["agentics/pks-agent-marketplace"] }`.

## Surfaces

- **Store**: `Permissions` type, `Owner.CanPush()`/`CanPull()`, `CreateOwner` (409 on
  exists), `SetPermissions`; `PutOwner` (password reset) preserves existing permissions.
- **Server**: `basicAuth` resolves the `*Owner` into request context; new
  `requireOwnerRead` middleware enforces pull scopes on tags/manifests/blobs reads;
  `requireOwnerWrite` adds the push-capability gate.
- **Mgmt API**: `POST /_mgmt/owners` accepts `push`/`pullScopes`; new
  `PUT /_mgmt/owners/{name}/permissions`; owner responses include `permissions`.
- **CLI**: `owner add <name> [--no-push] [--pull <scope>]...` and
  `owner perms <name> [--push] [--pull <scope>]... | --full`.
- **Admin portal** (agentics.dk `www-site`): "New customer" defaults to pull-only scoped
  to the marketplace image (advanced field for extra scopes); per-owner permission badges
  and an "Access" editor.

## Consequences

- Customer credentials can be minted that are pull-only and image-scoped — closes both the
  "customers could push" and "customers could read other customers' images" holes.
- Back-compatible: existing owners are unaffected until explicitly given a permissions block.
- Scopes are coarse globs over `owner/name`; tag-level or action-level (delete vs push)
  granularity is out of scope and can layer on later if needed.
- The trusted-proxy bypass remains an all-or-nothing anonymous read path; deployments that
  need scoped reads everywhere should not configure `TrustedProxyCIDRs`.
