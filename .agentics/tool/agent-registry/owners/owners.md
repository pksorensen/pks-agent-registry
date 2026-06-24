---
title: "Owners & permissions"
description: "The per-owner permission model: pull/push capability and image-path pull scopes."
tags: [owners, permissions, security]
category: agents
status: stable
type: cli
---

# Owners & permissions

An **owner** is a credential (name + password) that authenticates to the
registry. Each owner carries a permission scope that controls what it can do.

## The model

| Capability | Controls |
|---|---|
| **push** | Whether the owner may push (write) manifests/blobs to repos under its own name. |
| **pull scopes** | A list of glob patterns (`path.Match`) of `‹owner›/‹name›` repo paths the owner may pull. |

- An owner created with **no permission flags** gets **full access** (legacy
  behaviour — push to its own namespace, pull anything). This keeps existing
  credentials working with no migration.
- Adding any flag switches the owner to an **explicit, restricted** scope.

## Create a scoped owner

Pull-only, limited to one image:

```bash
REGISTRY_PASSWORD='s3cret' agent-registry owner add acme \
  --no-push \
  --pull 'agentics/pks-agent-marketplace'
```

Pull-only across several images (repeat `--pull`, globs allowed):

```bash
REGISTRY_PASSWORD='s3cret' agent-registry owner add acme \
  --no-push \
  --pull 'agentics/pks-agent-*' \
  --pull 'agentics/shared/*'
```

The password is read from `REGISTRY_PASSWORD`, or from stdin if that env var is
unset.

## Change an owner's permissions

```bash
# Replace scopes — pull-only, two image globs, no push:
agent-registry owner perms acme --pull 'agentics/pks-agent-*' --pull 'agentics/demo'

# Grant push (to the owner's own namespace) as well:
agent-registry owner perms acme --push --pull 'agentics/pks-agent-*'

# Restore unrestricted full access:
agent-registry owner perms acme --full
```

## Lifecycle

```bash
agent-registry owner list                 # list owners + their scopes
agent-registry owner password acme        # rotate the password
agent-registry owner delete acme          # remove the owner
```

## How enforcement works

- **Reads** (pull) are allowed when the target `‹owner›/‹name›` matches one of
  the owner's pull-scope globs (or the owner has full access). The catalog
  listing is filtered to only the repos an owner may pull.
- **Writes** (push) require the push capability **and** that the repo path's
  owner segment equals the authenticated owner — you can only push into your own
  namespace.

This is what makes customer credentials safe: a `--no-push --pull
'agentics/pks-agent-marketplace'` owner can pull exactly that one image and
nothing else, and can never push.
