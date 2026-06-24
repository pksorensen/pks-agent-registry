---
title: "Agent Registry"
description: "Self-hosted OCI container registry with per-owner pull/push permission scopes — one Go binary that's both the server and the admin CLI."
tags: [cli, registry, oci, docker, self-hosted]
category: agents
status: stable
type: cli
icon: package
author: Poul Kjeldager
component: agent-registry
usage: "agent-registry <command> [options]"
examples:
  - command: "agent-registry owner add acme --no-push --pull 'agentics/pks-agent-marketplace'"
    description: "Create a pull-only customer owner scoped to one image"
---

# Agent Registry

`agent-registry` is a self-hosted [OCI](https://github.com/opencontainers/distribution-spec)
container registry with a folder-backed store (no database) and **per-owner
permission scopes** — every credential can be limited to pull-only and to a glob
of image paths. The same single binary is both the **server** and the **admin
CLI**, so the command you install can stand up a registry *and* manage its owners
from your laptop against a remote one.

## Two ways to run it

- **Server:** `agent-registry serve` (or no args) starts the registry, serving
  the OCI `/v2/` API on `REGISTRY_ADDR` with state under `USER_DATA_DIR`.
- **Admin CLI:** any non-`serve` subcommand manages owners, repos, and tags.
  Point it at a remote registry with `REGISTRY_REMOTE` + `REGISTRY_ADMIN_TOKEN`
  to administer a deployed instance (e.g. `registry.agentics.dk`) without SSH.

## Quick start

```bash
curl -fsSL https://agentics.dk/install/agent-registry.sh | bash
agent-registry version

# Manage a remote registry's owners from anywhere:
export REGISTRY_REMOTE=https://registry.agentics.dk
export REGISTRY_ADMIN_TOKEN=<token>
agent-registry owner list
```

See [Quickstart](/tools/agent-registry/quickstart) for install options and a
first owner, [Owners & permissions](/tools/agent-registry/owners) for the
scoped-credential model, and [Reference](/tools/agent-registry/reference) for
every command and environment variable.

## Why it exists

- **Customer-safe credentials.** Issue pull-only owners scoped to a single
  image, so a customer can `docker pull` your product but can't push or read
  anything else.
- **No database.** All state is plain files under `USER_DATA_DIR`; `tar czf` is a
  complete backup.
- **Standards-compliant.** Works with `docker`, `buildx`, and multi-arch images
  (including OCI 1.1 attestation/referrers), so the normal Docker workflow just
  works.
