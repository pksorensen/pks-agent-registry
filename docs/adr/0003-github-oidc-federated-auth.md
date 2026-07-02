# ADR 0003 — GitHub OIDC federated auth (Distribution token service + trust bindings)

- Status: Accepted
- Date: 2026-07-01

## Context

Customers pull our images (e.g. `agentics/pks-agent-marketplace`) with static
owner credentials (ADR 0001). That leaves a long-lived secret in their CI and —
when their runtime (Azure Container Apps pulls on **every** container start and
supports only username/password for non-ACR registries) points directly at us —
makes registry.agentics.dk a live runtime dependency of customer deployments.

We want the pattern every cloud federation uses (Azure federated credentials,
AWS STS, Google WIF): the customer's GitHub Actions workflow presents its
short-lived OIDC identity token (fixed 5-minute lifetime, mintable at any point
in a job), we validate it against a configured trust rule, and we hand back our
own short-lived credential for the actual work. The customer pipeline then
mirrors the image into their own ACR, taking us out of their runtime path.

Where should the token logic live? Survey of real registries: Harbor, Quay and
zot embed their token service in the registry; GitLab's lives in the product
app. Nobody delegates the Docker token realm to a general-purpose IdP —
Keycloak's `docker-v2` protocol is disabled-by-default, authorizes all-or-
nothing, and cannot accept external JWTs without custom SPIs. zot v2.1.14 and
Quay's robot-account federation implement exactly this feature registry-side.

## Decision

Implement the standard Docker Distribution token-auth handshake **inside the
registry**, with GitHub OIDC as a second credential type, governed by
**trust bindings**.

### Token service

- `REGISTRY_PUBLIC_URL` arms the feature. `/v2/` 401s then advertise **both**
  challenges: `Bearer realm="<PublicURL>/token",service="<host>"` (preferred by
  docker/oras/crane) and `Basic realm="registry"` (legacy clients). Unset, the
  registry behaves exactly as before.
- `GET /token` authenticates Basic-carried credentials — a static owner
  password (bcrypt, ADR 0001) **or** a GitHub Actions OIDC JWT (detected by
  shape; username ignored) — and mints a registry-signed access token:
  ES256, self-generated P-256 key persisted at `<dataDir>/token/signing.key`,
  **30-minute TTL**, claims per the Distribution token spec
  (`access: [{type, name, actions}]` = the intersection of the requested
  `scope` params with what the principal's permissions allow; disallowed
  actions are silently dropped, scope-less requests still yield a token —
  that's the `docker login` probe).
- The data plane accepts three credential forms on `/v2/`: registry-minted
  Bearer tokens, static Basic, and raw OIDC-JWT-as-Basic-password
  (belt-and-braces for clients that ignore the Bearer challenge; note the
  GitHub JWT then expires ~5 min into a long pull — the token flow is the
  supported path).
- Bearer principals that hit an authorization wall get **401 +
  `Bearer ... scope="repository:<o>/<n>:pull[,push]",error="insufficient_scope"`**
  so conforming clients transparently re-fetch a correctly scoped token; Basic
  principals keep the existing 403s.
- Enforcement of bearer tokens is **stateless** — the token's `access` claims
  are projected onto the existing `Permissions` model; no per-request binding
  lookup. Consequence: revoking a binding/owner takes effect at token expiry
  (≤30 min). Accepted; a jti denylist can be added later if needed.

### Trust bindings

`<dataDir>/federation/<id>.json`, managed via `/_mgmt/federation` + CLI:

- `repository` ("org/repo"), optional `environment` (Azure-style: a binding is
  either repo-wide or pinned to one GitHub environment), `permissions`
  (reuses ADR 0001's `{push, pullScopes}`; always explicit — a binding can
  never carry legacy full access), optional `owner` = the namespace the
  identity acts as (required for push).
- **Immutable-ID pinning (TOFU)**: GitHub's `repository_id`/
  `repository_owner_id` claims are pinned on binding creation (when the admin
  surface can resolve them) or on first successful token issuance. A pinned
  binding matches by IDs only — repo renames keep working, name-squatting
  after a delete does not. Unpinned bindings match case-insensitively by name
  until first use.
- Validation: RS256 signature against the issuer JWKS
  (`REGISTRY_GH_OIDC_ISSUER`, default GitHub; JWKS cached 6 h, unknown-kid
  refetch rate-limited to 1/min, stale-served on fetch error), `iss` exact,
  `aud` must contain the registry hostname, exp/nbf with 60 s clock-skew
  leeway.
- Federated principals are surfaced as `fed:<org>/<repo>` (can never collide
  with owner names — `:`/`/` are invalid there).

## Consequences

- Customer CI needs only `permissions: id-token: write` plus
  `docker login <host> -u oauth2 -p $GITHUB_OIDC_JWT` — no static secrets on
  either side; the 5-minute GitHub JWT is consumed once at `/token` and the
  transfer runs on our 30-minute token (the same exchange-once architecture as
  Azure/AWS/Google).
- Fully backward compatible: feature dark without `REGISTRY_PUBLIC_URL`; static
  Basic keeps working on `/v2/` forever; the trusted-proxy anonymous-read
  bypass is checked before any credential logic.
- `_catalog` for bearer principals is filtered to the token's granted scopes
  (own namespace + scoped repos), which is narrower than the same owner's
  Basic-auth catalog — acceptable, docker doesn't use `_catalog`.
- GitHub JWKS outage blocks new OIDC logins (static credentials unaffected).
- Key rotation = delete `token/signing.key` + restart (outstanding tokens die;
  clients re-auth transparently).
