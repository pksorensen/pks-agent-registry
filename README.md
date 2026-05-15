# pks-agent-registry

A minimal Go OCI container registry (Docker Registry V2 / OCI Distribution Spec) with a single-binary admin CLI baked in. Designed for `registry.agentics.dk` and similar small, self-hosted registry needs where running the full `distribution/distribution` reference image is overkill.

> **v0 scope**: Basic-auth, owner+repo tenancy, filesystem-backed storage under `USER_DATA_DIR`. Push/pull works with `docker`, `podman`, `skopeo`, `crane`. No TLS — terminate at a reverse proxy (Traefik, Caddy, nginx).

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

Bearer/scope-based OAuth (per-repo, per-action tokens) is out of scope for v0 — Basic is what the OCI Distribution Spec explicitly allows, and is what every client supports. ([Token spec](https://distribution.github.io/distribution/spec/auth/token/) is the future upgrade path.)

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
