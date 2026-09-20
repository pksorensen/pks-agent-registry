# pks-agent-registry

A minimal Go OCI container registry (Docker Registry V2 / OCI Distribution Spec) with a single-binary admin CLI baked in. Designed for `registry.agentics.dk` and similar small, self-hosted registry needs where running the full `distribution/distribution` reference image is overkill.

> **v0 scope**: Basic-auth, owner+repo tenancy, filesystem-backed storage under `USER_DATA_DIR`. Push/pull works with `docker`, `podman`, `skopeo`, `crane`. No TLS — terminate at a reverse proxy (Traefik, Caddy, nginx).

Image push/pull stays the `docker` (or `podman`/`skopeo`/`crane`) CLI's job. What this binary adds on top is the server, the admin verbs, and — since [ADR 0004](docs/adr/0004-interactive-sign-in-and-docker-credential-helper.md) — signing a *person* in (`agent-registry login`) and answering Docker's credential-helper protocol on their behalf.

## Architecture

Two surfaces, one binary, one volume:

1. **OCI v2 API** — `/v2/...` — speaks the standard registry protocol so `docker push` / `docker pull` work unmodified.
2. **Management API** — `/_mgmt/...` — JSON REST API protected by a Bearer admin token, designed for the future web UI.

The same binary is also an **admin CLI** — invoke any non-`serve` subcommand via `docker exec` to manage owners/repos/tags directly against the filesystem (no server round-trip required).

## Data Model

| Concept | Description |
|---|---|
| **Owner** | A namespace + a Basic-auth credential. An owner can push/pull anything under `<owner>/*`. Created explicitly via the CLI or mgmt API. |
| **Repository** | `<owner>/<name>` — materializes on first push. No pre-creation needed. |
| **Tag** | A pointer from a string name (`latest`, `v1.2.3`) to a manifest digest. |
| **Blob** | Content-addressed bytes (image layer or config). Deduplicated across all owners by sha256 digest. |

## Environment Variables

| Variable               | Default  | Description                                                              |
|------------------------|----------|--------------------------------------------------------------------------|
| `USER_DATA_DIR`        | `/app/user-data` | Persistent storage path                                          |
| `REGISTRY_ADDR`        | `:5000`  | HTTP listen address                                                      |
| `REGISTRY_ADMIN_TOKEN` | (empty)  | Bearer token for `/_mgmt/` endpoints. Management API is disabled if unset. |
| `REGISTRY_PASSWORD`    | (empty)  | Used as the password by the CLI when stdin is not a TTY                  |
| `REGISTRY_REMOTE`      | (empty)  | Target URL for the CLI's *remote admin* mode (e.g. `https://registry-uat.agentics.dk`). When set, admin subcommands talk to that server's `/_mgmt/` API instead of the local filesystem. Requires `REGISTRY_ADMIN_TOKEN`. |
| `REGISTRY_TRUSTED_PROXY_CIDRS` | (empty) | Comma-separated CIDRs. When the TCP source IP of a `GET`/`HEAD` request on `/v2/*` falls in one of these networks, the request is served without Basic-auth. Intended for reverse-proxied deployments where the proxy fronts a trusted private network (e.g. a Coolify/Traefik homelab bridge). Writes always require auth. Example: `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8`. |
| `REGISTRY_PUBLIC_URL`  | (Coolify-derived) | Public base URL, e.g. `https://registry.agentics.dk`. Arms the Distribution token service + **GitHub OIDC federation** ([ADR 0003](docs/adr/0003-github-oidc-federated-auth.md)): `/v2/` 401s advertise a `Bearer realm="<url>/token"` challenge, `/token` mints 30-min registry tokens, and GitHub Actions workflows can `docker login -u oauth2 -p $GITHUB_OIDC_JWT` against configured trust bindings (`federation` CLI / `/_mgmt/federation`). Falls back to the Coolify-injected `COOLIFY_URL`, then `COOLIFY_FQDN` (first domain, `https://` assumed), so Coolify deployments arm it automatically. Unset everywhere = Basic-only (previous behavior). The hostname is the required OIDC token audience. |
| `REGISTRY_GH_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | Override the accepted OIDC issuer (tests / GitHub Enterprise Server). |
| `REGISTRY_AZURE_OIDC_AUDIENCE` | `api://AzureADTokenExchange` | Enables Microsoft Entra workload federation for explicitly approved Azure managed identities. The default lets cross-tenant identities present the same short-lived assertion used by Entra workload federation without a customer secret or per-tenant resource-app consent. A private deployment may configure its own Application ID URI, or set `off` to disable Azure federation. Tenant, client and object IDs must all match a stored `azure` trust binding. |
| `REGISTRY_KEYCLOAK_ISSUER` | `https://login.agentics.dk/realms/agentics` | Keycloak realm URL. Arms **interactive human sign-in** ([ADR 0004](docs/adr/0004-interactive-sign-in-and-docker-credential-helper.md)): `agent-registry login` mints a Keycloak token in the browser, and `/token` accepts it as a second credential type against `keycloak` trust bindings. Inheriting the default grants nobody anything without a trust binding. Set it to another realm to use one, or to `off` to disable interactive sign-in entirely. |
| `REGISTRY_KEYCLOAK_CLIENT_ID` | `agent-registry-cli` | The public OAuth client the CLI signs in as, advertised to it in this registry's `/.well-known/oauth-protected-resource`. One client per tool, not one per house. Not a secret. |
| `REGISTRY_KEYCLOAK_AUDIENCE` | (registry hostname) | The audience a Keycloak token must carry. A default Keycloak access token carries only `account`, and Keycloak ignores the RFC 8707 `resource` parameter, so the realm needs an audience mapper on the CLI's client for this value — `keycloak/reconcile-cli-client.mjs` adds it. Without it a token from any client in the realm would be replayable here. |
| `REGISTRY_KEYCLOAK_ACCEPT_AZP` | (empty) | **Relaxes the check above.** Accepts a token whose `aud` omits this registry when its `azp` equals this client id. For a bare third-party realm where nobody can add a mapper. Off by default and logged loudly when on, because it accepts exactly the replay the audience exists to reject. |
| `REGISTRY_KEYCLOAK_SCOPES` | `openid offline_access` | Scopes the CLI requests, advertised as `scopes_supported` in the metadata document so the resource decides, not the client. `offline_access` is what keeps the Docker credential helper working past Keycloak's SSO idle timeout. |

## Storage Layout

```
$USER_DATA_DIR/
  blobs/sha256/<aa>/<digest>           # content-addressed, shared across owners
  uploads/<id>                         # in-flight upload sessions
  repos/<owner>/<name>/
    manifests/<digest-hex>             # manifest body
    manifests/<digest-hex>.mediatype   # one-line text file
    tags/<tag>                         # text file containing "sha256:..."
  owners/<owner>.json                  # {name, passwordHash (bcrypt), createdAt}
```

Everything is plain files — `tar`-friendly backups, no embedded database.

## Install the CLI

The `agent-registry` binary (server **and** admin CLI) ships as a prebuilt
binary via the agentics.dk release store — no source checkout needed.

**Linux / macOS**

```bash
curl -fsSL https://agentics.dk/install/agent-registry.sh | bash
```

**Windows (PowerShell)**

```powershell
irm https://agentics.dk/install/agent-registry.ps1 | iex
```

Pin a version or customize the install:

```bash
curl -fsSL https://agentics.dk/install/agent-registry.sh | VERSION=1.2.1 bash
curl -fsSL https://agentics.dk/install/agent-registry.sh | INSTALL_DIR=~/bin NO_MODIFY_PATH=1 bash
```

The script detects your OS/architecture, verifies the sha256 checksum, installs
`agent-registry` to `~/.local/bin` (or `%LOCALAPPDATA%\Agentics\bin` on Windows),
and ensures it is on your `PATH`. Then administer a remote registry from your
machine:

```bash
export REGISTRY_REMOTE=https://registry.agentics.dk REGISTRY_ADMIN_TOKEN=<token>
agent-registry owner list
```

Full docs: <https://agentics.dk/tools/agent-registry>.

## Quick Start

```bash
docker run -d \
  --name agent-registry \
  --restart unless-stopped \
  -p 5000:5000 \
  -v agent-registry-data:/app/user-data \
  -e REGISTRY_ADMIN_TOKEN=$(openssl rand -hex 32) \
  registry.kjeldager.io/agent-registry:latest

# Create your owner (you'll be prompted for a password):
docker exec -it agent-registry ./agent-registry owner add pksorensen

# Push an image:
docker login localhost:5000 -u pksorensen
docker tag alpine:3.21 localhost:5000/pksorensen/alpine:3.21
docker push localhost:5000/pksorensen/alpine:3.21
```

## Signing in (people)

`docker login` has no OAuth for third-party registries — the CLI takes a
username and a password and nothing else. So the browser flow lives here
instead, and Docker is reached through the one extension point it does have:
a credential helper.

```bash
agent-registry login                    # defaults to registry.agentics.dk
```

That prints a URL, opens a browser if there is one, and waits for the callback
on `127.0.0.1`. Nothing is transcribed — including inside a devcontainer or an
editor's remote session, because the editor forwards the port, which is the same
reason `gh auth login` works in there.

When the callback genuinely cannot reach this machine — a raw SSH login, a tmux
pane with no forwarding — the sign-in continues by itself with the OAuth 2.0
**device grant** and prints a URL with the code already in it. `--device` picks
that up front; `--browser` insists on the callback. See the house standard,
**ADR 0010 — House CLI sign-in**, in the agentic-live-www workspace under
`docs/adr/`.

On success it offers to register itself as Docker's credential helper for that
registry. Say yes and `docker pull` just works from then on: Docker asks
`docker-credential-agentics` on **every** operation, and the helper hands back
a freshly refreshed token. Nothing long-lived is written to
`~/.docker/config.json`.

```bash
agent-registry whoami                   # who am I, and does docker know?
agent-registry token                    # print a fresh token (for scripts/CI)
agent-registry logout                   # end the session, forget the credential
agent-registry credential-helper install|uninstall|status [<registry>]
```

Without the helper, a one-off login that lasts until the token expires:

```bash
docker login registry.agentics.dk -u oauth2 -p "$(agent-registry token)"
```

Credentials live in `~/.config/agent-registry/credentials.json` (mode `0600`).
The `credHelpers` entry the installer writes is **per-registry**, so it sits
beside a global `credsStore` — including the VS Code dev-containers helper that
rewrites `credsStore` on reconnect — without either one fighting the other.

Access is granted by a trust binding, not by an owner account:

```bash
agent-registry federation add-user poul --pull 'agentics/*'
agent-registry federation add-group developers --pull 'agentics/*'
```

A username binding pins to that person's Keycloak subject on first use (TOFU),
so a later username change cannot hand it to someone else. A group binding is
never pinned — it grants to the membership. Both need
`REGISTRY_KEYCLOAK_ISSUER` set on the server — it defaults to the Agentics
realm — and group bindings need a group-membership mapper on the
`agent-registry-cli` client, which the reconcile script below adds.

### Arming it on a realm

One script, then the first grant. The script is needed because a realm import
only runs when the realm is *created* — editing `agentics-realm.json` does not
change a realm that already exists, which is how the device grant came to be
switched off in production while the JSON said it was on.

It lives in the **agentic-live-www** workspace under `keycloak/`, not in this
repository — this registry is one consumer of that realm, not its owner. It is
idempotent, and everything it does can also be clicked in the Keycloak console.

```bash
# 1. create/reconcile this CLI's own public client
KEYCLOAK_URL=https://login.agentics.dk KC_BOOTSTRAP_ADMIN_PASSWORD=... \
  node keycloak/reconcile-cli-client.mjs \
    --client-id agent-registry-cli \
    --audience registry.agentics.dk

# 2. arm the registry, then grant someone access
#    (REGISTRY_KEYCLOAK_ISSUER already defaults to the Agentics realm)
agent-registry federation add-user poul --pull 'agentics/*'
```

One pass reconciles the loopback redirect URIs (`http://127.0.0.1:*` and
`http://localhost:*`), PKCE `S256`, the device grant, an audience mapper on the
client's *dedicated* mappers so every token it mints carries
`aud: registry.agentics.dk`, and a group-membership mapper so `groups` reaches
the token at all — without that one, group trust bindings silently never match.
Each CLI gets its own client, so the next one is another invocation of the same
script rather than another script.

Check it without an admin password. A reconciled client returns a
`device_code` and a `verification_uri_complete`; one that does not exist yet
returns `invalid_client`/`unauthorized_client`:

```bash
curl -s -X POST \
  https://login.agentics.dk/realms/agentics/protocol/openid-connect/auth/device \
  -d client_id=agent-registry-cli -d 'scope=openid offline_access' \
  -d code_challenge_method=S256 \
  -d code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

The PKCE parameters are not optional here even though RFC 8628 says nothing
about them: the client enforces `S256`, so Keycloak rejects a device request
without a challenge (`Missing parameter: code_challenge_method`). The value
above is the fixed example challenge from RFC 7636 — fine for a liveness probe,
since nothing exchanges the code.

Full design in [ADR 0004](docs/adr/0004-interactive-sign-in-and-docker-credential-helper.md)
— amended by the house standard, **ADR 0010 — House CLI sign-in**, in the
agentic-live-www workspace under `docs/adr/`, which is where the flow, the
`client_id` extension and the audience mechanism are worked through.

## Admin CLI

The CLI runs in one of two modes:

- **Local** (default) — operates directly on `USER_DATA_DIR` on disk. Use this via `docker exec` on the running container, or directly on the host. Works even when the HTTP server isn't running.
- **Remote** — set `REGISTRY_REMOTE` + `REGISTRY_ADMIN_TOKEN` and the same subcommands hit the live `/_mgmt/` API over HTTP. Use this from a laptop, CI job, or anywhere outside the container.

```bash
# Local (inside the container):
docker exec -it agent-registry ./agent-registry owner add pksorensen

# Remote (from anywhere):
export REGISTRY_REMOTE=https://registry-uat.agentics.dk
export REGISTRY_ADMIN_TOKEN=$(pass show coolify/registry-uat/admin-token)
agent-registry owner list
agent-registry repo list pksorensen
agent-registry tag delete pksorensen/hello-world:smoke
agent-registry gc
```

Image push/pull stays the docker (or podman/skopeo/crane) CLI's job — the admin verbs below are everything our binary adds on top.

```bash
# Owners
agent-registry owner add <name>                # password via stdin or REGISTRY_PASSWORD
agent-registry owner list
agent-registry owner password <name>           # rotate
agent-registry owner delete <name>

# Repos + tags
agent-registry repo list [<owner>]
agent-registry repo delete <owner>/<name>
agent-registry tag list <owner>/<name>
agent-registry tag delete <owner>/<name>:<tag>

# Maintenance
agent-registry gc                              # remove blobs not referenced by any manifest
agent-registry serve                           # run the HTTP server (default if no subcommand)
agent-registry help
```

Non-interactive password use (CI, scripted setup):

```bash
docker exec -e REGISTRY_PASSWORD=hunter2 agent-registry ./agent-registry owner add pksorensen
```

## Management API

Disabled unless `REGISTRY_ADMIN_TOKEN` is set. All endpoints require `Authorization: Bearer <token>`.

| Method | Path | Purpose |
|---|---|---|
| `GET`    | `/_mgmt/health`                                 | Liveness (no auth) |
| `GET`    | `/_mgmt/owners`                                 | List owners |
| `POST`   | `/_mgmt/owners`                                 | Create owner — body `{name, password}` |
| `PUT`    | `/_mgmt/owners/{name}/password`                 | Rotate password — body `{password}` |
| `DELETE` | `/_mgmt/owners/{name}`                          | Delete owner |
| `GET`    | `/_mgmt/repos?owner=<name>`                     | List repos (filter optional) |
| `DELETE` | `/_mgmt/repos/{owner}/{name}`                   | Delete a repo |
| `GET`    | `/_mgmt/repos/{owner}/{name}/tags`              | List tags |
| `DELETE` | `/_mgmt/repos/{owner}/{name}/tags/{tag}`        | Delete a tag |
| `POST`   | `/_mgmt/gc`                                     | Run blob garbage collection |

The future web UI in `agentic-live-www` will consume this API.

## Auth Model

- **OCI v2** uses HTTP Basic against the owner credentials. Reads (GET/HEAD) require any valid owner; writes (PUT/POST/PATCH/DELETE) additionally require the path's `<owner>` segment to match the authenticated user.
- **Management API** uses a single Bearer admin token from `REGISTRY_ADMIN_TOKEN`. The CLI bypasses this entirely by operating on the filesystem directly.

- **Federated identities** authenticate with a JWT presented as the Basic password at `GET /token`, matched against a trust binding. GitHub Actions, Keycloak, and explicitly approved Azure managed identities are supported. The token realm itself stays ours — external identity providers are credential types, not the realm.

When `REGISTRY_PUBLIC_URL` is set, `/v2/` 401s also advertise a `Bearer realm="<url>/token"` challenge and `/token` mints 30-minute, scope-limited registry tokens. Enforcement of those is stateless, so revoking access takes effect at token expiry.

## Deployment

### Option A: Docker on a Hetzner host

```bash
docker run -d \
  --name agent-registry \
  --restart unless-stopped \
  -p 127.0.0.1:5000:5000 \
  -v agent-registry-data:/app/user-data \
  -e REGISTRY_ADMIN_TOKEN=$(openssl rand -hex 32) \
  registry.kjeldager.io/agent-registry:latest
```

Front with Traefik/Caddy/nginx for TLS. The container itself does HTTP only.

**To update:**

```bash
docker pull registry.kjeldager.io/agent-registry:latest
docker restart agent-registry
```

### Option B: Coolify

1. Add a new service → Docker Image → `registry.kjeldager.io/agent-registry:latest`
2. Set env: `REGISTRY_ADMIN_TOKEN=<long-random>`
3. Add persistent volume: container path `/data`
4. Let Coolify's Traefik handle TLS for `registry.agentics.dk` → port 5000

## Reverse-proxy notes

Container registries push **large** request bodies. If you front this with Traefik/nginx/Caddy, make sure:

- Body-size limit is raised — Traefik `--entryPoints.web.transport.respondingTimeouts.readTimeout=300s` and no client_max_body_size cap; nginx `client_max_body_size 0;`.
- `proxy_request_buffering off;` (nginx) or equivalent so layer uploads stream through rather than buffering to disk in the proxy.
- Read/write timeouts are long enough for slow uplinks — 10+ minutes is reasonable.

## Going Live / Future Warnings

**No TLS** — the binary speaks plain HTTP. Always terminate TLS at a reverse proxy in production. Docker refuses to push to a non-TLS registry unless it's `localhost` or listed in `daemon.json` under `insecure-registries`.

**Basic-only auth** — credentials hit the network on every request (encrypted by TLS at the proxy). Once you have more than a handful of owners or need per-action scopes, upgrade to the Bearer token spec.

**No cross-repo mount** — the optional `?mount=<digest>&from=<other_name>` endpoint isn't implemented in v0. Clients fall back to re-uploading; blobs still dedupe in storage on finalize.

**No chunked download (`Range`)** — pulls return the whole blob in one response. Fine for layers up to a few hundred MB; add `Range` support if you start pushing GB-sized images.

**`gc` is not concurrent-safe with active pushes** — run it during quiet periods, or stop the server first. v0 doesn't track in-flight uploads against the GC scan.

**Sidecar pattern is absent** — unlike `pks-agent-inbox` / `pks-agent-ftp`, this project doesn't write Markdown sidecars for every push. The future direction (push events fed into an agent pipeline) would add a `webhooks/` config or fsnotify watcher on `repos/`.

## Building from source

```bash
cd src/agent-registry
go build ./...
./agent-registry serve
```

## Related projects

- [pks-agent-inbox](https://github.com/pksorensen/pks-agent-inbox) — same shape, but SMTP-receiving
- [pks-agent-ftp](https://github.com/pksorensen/pks-agent-ftp) — same shape, but FTP-receiving
