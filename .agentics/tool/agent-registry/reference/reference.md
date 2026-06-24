---
title: "Reference"
description: "Every agent-registry command and environment variable."
tags: [reference, cli, env]
category: agents
status: stable
type: cli
---

# Reference

## Commands

```
agent-registry serve                                 Run the registry server (default when no args)
agent-registry version                               Print the build version

agent-registry owner add <name> [--no-push] [--pull <scope>]...
                                                     Create an owner (password from REGISTRY_PASSWORD or stdin).
                                                     No flags → full access; --no-push → pull-only;
                                                     --pull <glob> → restrict pulls to matching repos.
agent-registry owner perms <name> [--push] [--pull <scope>]... | --full
                                                     Replace an owner's permissions (--full restores full access).
agent-registry owner list                            List owners and their scopes
agent-registry owner password <name>                 Reset an owner's password
agent-registry owner delete <name>                   Delete an owner

agent-registry repo list [<owner>]                   List all repos, or those under an owner
agent-registry repo delete <owner>/<name>            Delete a repo (all manifests + tags)

agent-registry tag list <owner>/<name>               List tags
agent-registry tag delete <owner>/<name>:<tag>       Delete a tag

agent-registry gc                                    Garbage-collect unreferenced blobs
```

Run `agent-registry help` for the built-in summary.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `USER_DATA_DIR` | `/data` | Root of the folder-backed store (server mode + local CLI mode). |
| `REGISTRY_ADDR` | `:5000` | Address the server listens on. |
| `REGISTRY_ADMIN_TOKEN` | — | Bearer token for the `/_mgmt/` API. The management API is disabled when unset. |
| `REGISTRY_REMOTE` | — | When set (with `REGISTRY_ADMIN_TOKEN`), admin subcommands target this remote registry's `/_mgmt/` API instead of the local filesystem. |
| `REGISTRY_PASSWORD` | — | Password used by `owner add` / `owner password` (falls back to stdin). |
| `REGISTRY_TRUSTED_PROXY_CIDRS` | — | Comma-separated CIDRs allowed anonymous `GET`/`HEAD` on `/v2/*` (for proxy-fronted deployments where the proxy enforces auth). Empty disables the bypass. |

## Local vs. remote admin

The same subcommands run in two modes:

- **Local** — no `REGISTRY_REMOTE`: the CLI operates directly on the store at
  `USER_DATA_DIR`. Use this on the registry host.
- **Remote** — `REGISTRY_REMOTE` + `REGISTRY_ADMIN_TOKEN` set: the CLI calls the
  remote registry's management API over HTTPS. Use this to administer a deployed
  registry (e.g. `registry.agentics.dk`) from your machine.

## Pull scope globs

Pull scopes match the full `‹owner›/‹name›` repo path with `path.Match`
semantics (`*` matches within a path segment). Examples:

| Scope | Matches |
|---|---|
| `agentics/pks-agent-marketplace` | exactly that repo |
| `agentics/pks-agent-*` | every `pks-agent-*` repo under `agentics` |
| `agentics/*` | every repo under `agentics` |
