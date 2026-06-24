---
title: "Quickstart"
description: "Install agent-registry and create your first scoped owner."
tags: [cli, install, quickstart]
category: agents
status: stable
type: cli
---

# Quickstart

## Install

**Linux / macOS**

```bash
curl -fsSL https://agentics.dk/install/agent-registry.sh | bash
```

**Windows (PowerShell)**

```powershell
irm https://agentics.dk/install/agent-registry.ps1 | iex
```

The script detects your OS/architecture, verifies the sha256 checksum, installs
the `agent-registry` binary to `~/.local/bin` (or `%LOCALAPPDATA%\Agentics\bin`
on Windows), and ensures it is on your `PATH`.

Pin a version or customize the install:

```bash
curl -fsSL https://agentics.dk/install/agent-registry.sh | VERSION=1.2.1 bash
curl -fsSL https://agentics.dk/install/agent-registry.sh | INSTALL_DIR=~/bin NO_MODIFY_PATH=1 bash
```

Verify:

```bash
agent-registry version
```

## Administer a remote registry

The admin subcommands talk to a deployed registry over its `/_mgmt/` API. Point
them at the host and provide its admin token:

```bash
export REGISTRY_REMOTE=https://registry.agentics.dk
export REGISTRY_ADMIN_TOKEN=<token>

agent-registry owner list
```

## Create your first owner

Give a customer **pull-only** access scoped to a single image:

```bash
REGISTRY_PASSWORD='s3cret' agent-registry owner add acme \
  --no-push \
  --pull 'agentics/pks-agent-marketplace'
```

The customer can now authenticate and pull only that image:

```bash
docker login registry.agentics.dk -u acme -p 's3cret'
docker pull registry.agentics.dk/agentics/pks-agent-marketplace:latest
```

A push, or a pull of any other repo, is denied. See
[Owners & permissions](/tools/agent-registry/owners) for the full scope model.

## Run a registry locally

```bash
USER_DATA_DIR=./data REGISTRY_ADDR=:5000 agent-registry serve
```

## Next steps

- [Owners & permissions](/tools/agent-registry/owners) — pull/push scopes and globs.
- [Reference](/tools/agent-registry/reference) — every command + environment variable.
