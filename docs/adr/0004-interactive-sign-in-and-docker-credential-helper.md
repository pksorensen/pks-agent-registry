# ADR 0004 — Interactive sign-in and a Docker credential helper

- Status: Accepted
- Date: 2026-08-25
- Supersedes: nothing. Extends [ADR 0003](0003-github-oidc-federated-auth.md).
- **Superseded in part (2026-08-25)** by **ADR 0010 — House CLI sign-in**,
  which lives in the agentic-live-www workspace under `docs/adr/` — this
  registry consumes that standard, it does not own it — and settles one flow
  for every CLI in the house. Its §3, §4 and §5 below carry amendment notes;
  the rest of this ADR stands.

## Context

ADR 0003 gave CI a way in without a stored secret: a GitHub Actions OIDC token,
presented as the Basic password at `GET /token`, matched against a trust
binding. It did nothing for people. A developer who wants to pull
`registry.agentics.dk/agentics/pks-agent-doorman:latest` still has to be handed
an owner password out of band, and then `docker login` with it — a shared
password, typed into a shell, cached in `~/.docker/config.json`, rotated never.

The concrete failure this ADR exists to remove: an Aspire AppHost whose
resources are container images from this registry fails to start on a fresh
machine with `error from registry: unauthorized`, and the only fix is finding
someone who knows the owner password.

The wish was "`agent-registry login` and then docker just works". Answering it
means answering what Docker actually supports.

### What Docker supports

- **`docker login` has no OAuth.** For third-party registries the CLI accepts
  `-u`, `-p` and `--password-stdin`, nothing else. The browser flow in Docker
  Desktop is Docker Hub-specific. The OAuth2 in the Distribution spec concerns
  the registry's *token endpoint*, not how the human gets a credential.
- **Credential helpers are the extension point.** A binary named
  `docker-credential-<name>` speaking `get` / `store` / `erase` / `list` as
  JSON over stdin/stdout — the closest thing Docker has to a Git credential
  helper, and it is closer than it looks: Docker calls `get` on *every*
  auth-needing operation, so a helper can mint a fresh short-lived credential
  per pull and never persist a long-lived one.
- **`credHelpers` is per-registry** and takes precedence over the global
  `credsStore` for that host, so ours can coexist with the VS Code
  dev-containers helper that owns `credsStore` and rewrites it on reconnect.

## Decision

**1. Keycloak becomes a second accepted credential type at `GET /token`.**

Not a second token realm. The Docker token realm stays ours, for the reasons
ADR 0003 recorded: Keycloak's `docker-v2` protocol is disabled by default,
authorizes all-or-nothing, and cannot accept external JWTs without custom SPIs.
What changes is only *which JWTs we will validate* on the way in. `/token`
already accepts a JWT-as-Basic-password and detects it by shape; it now routes
that JWT by its (unverified) `iss` claim to either the GitHub validator or the
Keycloak one, each of which re-reads `iss` from the signed payload and rejects a
mismatch. Routing on an unverified claim decides nothing but which verifier
runs.

Armed by `REGISTRY_KEYCLOAK_ISSUER`. Unset, the registry behaves exactly as
before.

**2. Trust bindings gain a Keycloak kind.**

A binding is now either `github` (a repository, optionally one environment) or
`keycloak` (one username, or any member of one group). A record with no `kind`
is a GitHub binding, so everything written before this ADR keeps working.

Username bindings pin to the Keycloak `sub` on first successful use, the same
TOFU move ADR 0003 makes on `repository_id`, so a later username change cannot
hand the binding to someone else. **Group bindings are never pinned** — pinning
one would lock the group's grant to whichever member logged in first, which is
the opposite of what a group binding means.

The minted registry token's subject is the *person* (`kc:<username>`), not the
binding, so three people sharing a group binding produce three distinct
subjects in the audit trail.

The issuer on a Keycloak binding is always the registry's own configured realm,
never a value the mgmt API caller supplies — an admin token must not be able to
point a binding at an issuer the registry does not otherwise trust.

**3. Audience is required, and is the registry hostname.**

Same rule as the GitHub path. A default Keycloak access token carries
`aud: ["account"]`, which would make any token minted for any client in the
realm replayable at the registry. Without the registry's own name in `aud` the
token is refused. Configurable as `REGISTRY_KEYCLOAK_AUDIENCE`, defaulting to
the hostname.

> **Amended 2026-08-25 — there is no `registry` client scope.** The rule above
> is unchanged; only the way the stamp gets onto the token has moved. This ADR
> had the CLI *request* a `registry` client scope carrying the audience mapper,
> which is what a **shared** client needs: a request-time switch, because one
> client id talks to several resources. ADR 0010 gives each tool its own client
> (`agent-registry-cli`), and a client that talks to exactly one resource wants
> the mapper on its **dedicated mappers**, firing on every token it mints. The
> scope was only ever the shared-client workaround, so it is removed rather
> than migrated. ADR 0010 §5 walks the whole thing through in plain HTTP,
> including the measured fact that Keycloak ignores the RFC 8707 `resource`
> parameter — which is why a mapper is required at all. An opt-in `azp`
> fallback (`REGISTRY_KEYCLOAK_ACCEPT_AZP`) exists for bare third-party realms
> and is off by default.

**4. Sign-in uses the device authorization grant, not a loopback redirect.**

The obvious design — open a browser, listen on `localhost`, catch the redirect
— requires the browser and the CLI to agree on a port on the same machine. In
this house the CLI runs in a devcontainer reached over SSH, in tmux, on a
remote box, or inside CI. The device grant needs only that the human can open
a URL *somewhere*, and the realm's `agentics-cli` client is a public client
that already supports it in principle.

Measured 2026-08-25, it is **off in production**: the device endpoint answers
`unauthorized_client` / "The flow is disabled for the client", even though
`agentics-realm.json` carries
`oauth2.device.authorization.grant.enabled: "true"`. A realm import does not
update an existing realm, so the flag never reached the live client. That is
what `keycloak/reconcile-cli-device-grant.mjs` exists to fix, and it is a
prerequisite for sign-in rather than an optional tidy-up.

`offline_access` is requested so the refresh token outlives the SSO idle
timeout; without it the credential helper stops working after about half an
hour.

> **Superseded 2026-08-25 — loopback leads, device follows.** The premise above
> is wrong. A browser *can* reach a loopback listener in a devcontainer or an
> editor's remote session, because the editor forwards the port — that is
> precisely why `gh auth login` and `az login` work in here, and `pks-cli`'s own
> `OidcLoopback.cs` says so in its class comment. Re-measured on the live realm
> the same day: a `http://localhost:<any port>/<any path>` redirect is
> **accepted** (200, login page rendered), so the loopback flow was working all
> along and the device flow was the one switched off.
>
> ADR 0010 therefore attempts loopback first (RFC 8252, PKCE S256,
> `127.0.0.1` on `[51789, 51790, 51791]`), and falls back to the device grant on
> a bind failure, a callback timeout, or a bare SSH login. `--device` forces the
> fallback, `--browser` forbids it. No predicate reads `DISPLAY`: a devcontainer
> has none and loopback works there anyway, so a `DISPLAY` check would route
> exactly the normal case down the fallback path.
>
> Everything this section says about the device grant remains true of it as the
> *fallback*, including that it was disabled on the live client and that a realm
> import does not update an existing realm. The reconcile script it names has
> been replaced by the parameterised `keycloak/reconcile-cli-client.mjs`, which
> arms redirect URIs, the device flag and the audience mapper in one pass.

**5. The registry publishes how to sign into it.**

`GET /.well-known/agent-registry-login` returns `{issuer, client_id, audience,
scopes, registry}`, unauthenticated — a client cannot sign in until it knows
where to. Every field is a public OAuth client parameter. `404` when
interactive sign-in is not configured, so the CLI says so plainly instead of
guessing.

> **Superseded 2026-08-25 — RFC 9728 instead of a bespoke document.** The idea
> is kept and the spelling is standard: the registry now serves Protected
> Resource Metadata at `GET /.well-known/oauth-protected-resource` and points at
> it from its `WWW-Authenticate` challenge with `resource_metadata="…"`, so a
> client that arrived by way of a failed `docker pull` can find the sign-in from
> the URL alone. `scopes_supported` comes from the resource, so the CLI requests
> what it is told to rather than carrying its own copy; `client_id` is a
> documented non-standard extension, because RFC 9728 has no field for a public
> client id and RFC 7591 dynamic registration is not something the providers we
> target have adopted.
>
> `GET /.well-known/agent-registry-login` was **deleted outright**, not
> deprecated: no CLI release ever shipped that spoke it, so an alias would have
> protected nothing.

**6. The CLI ships the credential helper, and offers to install it.**

After a successful `agent-registry login`, the CLI asks whether Docker should
use the sign-in. Yes installs a `docker-credential-agentics` next to the binary
(a symlink on Unix, recognised by `argv[0]`; a `.cmd` shim on Windows, where
symlinks need a privilege) and adds a `credHelpers` entry for that one
registry. No prints the two commands instead. Non-interactive stdin never
prompts.

`get` returns `oauth2` as the username, deliberately **not** the magic
`<token>`, which makes Docker treat the secret as an identity token and switch
to an OAuth2 POST refresh flow this registry does not implement. It refreshes
silently when the cached access token is within a minute of expiry.

A stored username/password (what `docker login` hands to `store`) is kept
alongside, so registering the helper does not break password login on a
registry with no Keycloak. The OIDC session wins when both exist.

## Consequences

- A developer runs `agent-registry login`, approves in a browser, and pulls.
  Nothing long-lived is written to `~/.docker/config.json`.
- Access is revoked by removing the trust binding or disabling the Keycloak
  account. Enforcement stays stateless: a minted registry token is honoured
  until it expires (≤30 min), as in ADR 0003.
- One deployment prerequisite, one-time and verified absent in production on
  2026-08-25: the `agent-registry-cli` client must exist on the realm, with its
  loopback redirect URIs, PKCE `S256`, the device grant, the audience mapper and
  the group-membership mapper — all of which `keycloak/reconcile-cli-client.mjs`
  arms in a single idempotent pass. `REGISTRY_KEYCLOAK_ISSUER` no longer has to be set, because it now
  defaults to the Agentics realm; inheriting that default still grants nobody
  anything without a trust binding. The script cannot be replaced by editing
  `agentics-realm.json`, because that file is only read when a realm is first
  created. Script and realm file both live in the agentic-live-www workspace,
  not in this repository: this registry consumes the realm, it does not own it.
  *(Amended 2026-08-25: this was three prerequisites and two scripts before
  ADR 0010 replaced the shared client and its `registry` scope with one client
  per tool.)*
- A realm where the client exists but the audience mapper does not is a state
  the deployment can pass through, and Keycloak reports nothing about it — it
  ignores the RFC 8707 `resource` parameter silently (measured), so a token
  simply comes back without the stamp. `agent-registry login` would then report
  success while the token was unusable, and the failure would resurface as an
  unexplained 401 at `docker pull`. The CLI therefore checks the `aud` claim of
  its own new token and says so on the spot.
- Group bindings need a group-membership mapper on that client. Without it
  group bindings simply never match; username bindings are unaffected.
- The credential file (`~/.config/agent-registry/credentials.json`, `0600`)
  holds a refresh token. That is a real secret on disk — a smaller one than a
  shared owner password, and revocable per person, but not nothing.

## Alternatives considered

- **Delegate the token realm to Keycloak's `docker-v2`.** Rejected in ADR 0003
  and still rejected: all-or-nothing authorization cannot express the pull-scope
  model, and it cannot accept GitHub tokens at all, so we would need both
  anyway.
- **Loopback redirect with PKCE.** Kept as a possible convenience for a machine
  with a local browser, not as the default, for the port-agreement reason above.
- **An identity-token / OAuth2 `POST /token` endpoint** (what ACR does, giving a
  `docker login` that survives restarts without a helper). Possible later; it is
  not a prerequisite for any of the above, and adding it to the critical path
  would double the work before anything is usable.
- **Static per-person owner accounts.** Works today, and is what we do now.
  It is a password per person, rotated by hand, with no connection to the
  account that person's access is actually governed by.
