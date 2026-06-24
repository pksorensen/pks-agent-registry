# ADR 0002 — OCI 1.1 referrers API + subject indexing

- Status: Accepted
- Date: 2026-06-24

## Context

Pulling a multi-arch image that carries buildx provenance/attestation manifests
from `registry.agentics.dk` failed on a modern Docker client (Engine 29 /
buildx) with:

```
docker pull registry.agentics.dk/agentics/pks-agent-marketplace:latest
latest: Pulling from agentics/pks-agent-marketplace
docker: failed to decode referrers index: EOF
```

Single-arch images built with plain `docker build` pulled fine — the regression
only hit images pushed by buildx / `docker/build-push-action` with default
provenance, which attach OCI **attestation manifests** and which trigger the
client to query the **OCI Distribution Spec 1.1 referrers API**
(`GET /v2/<name>/referrers/<digest>`).

### Root cause

The registry had **no route** for `/v2/{owner}/{name}/referrers/{digest}`.
Crucially this did **not** surface as a clean `404`: the base route
`GET /v2/` (`handleV2Base`) is a prefix pattern in Go's `http.ServeMux`, so any
unmatched `/v2/...` GET fell through to it and returned **`200 OK` with an empty
body**. The Docker client then tried to JSON-decode that empty body as an OCI
image index and failed with `EOF`. (A real `404` would have let the client fall
back to the tag-schema lookup; a `200`-empty actively breaks it.)

A secondary gap: manifests carrying an OCI `subject` (the attestation manifests)
were stored but never indexed, so even a correct referrers endpoint would have
returned nothing for them, and the `OCI-Subject` response header was not set on
manifest `PUT`.

## Decision

Implement the referrers API and subject indexing per OCI Distribution Spec 1.1.

**Routing / handler** (`internal/server`):

- Add `GET /v2/{owner}/{name}/referrers/{digest}`, gated by `requireOwnerRead`
  like the other read endpoints.
- The handler **always** returns `200` with a valid
  `application/vnd.oci.image.index.v1+json` document (correct `Content-Type`),
  whose `manifests` array is the set of referring descriptors — **empty `[]`,
  never `null`**, when there are none. This is the direct fix for the EOF.
- Support the optional `?artifactType=<type>` filter; when filtering is applied,
  set the `OCI-Filters-Applied: artifactType` header.
- On manifest `PUT`, when the body carries a `subject`, echo `OCI-Subject:
  <digest>`.

**Storage** (`internal/store`, folder-backed, no DB — consistent with the
existing conventions):

- On `PutManifest`, best-effort parse the body for `subject`, `artifactType`,
  config `mediaType` and `annotations`. When a valid `subject` digest is
  present, write the referring manifest's OCI descriptor to
  `repos/<owner>/<name>/referrers/<subjectHash>/<referrerHash>.json`.
- `ListReferrers(owner, name, subjectDigest, artifactType)` reads that directory
  and returns descriptors (stable order, non-nil slice). `artifactType` filters
  by exact match.
- Per spec, the descriptor's `artifactType` is the manifest's top-level
  `artifactType`, falling back to the config descriptor's `mediaType` (the shape
  buildx provenance manifests use).
- `DeleteManifest` best-effort removes the referrer index entry (it reads the
  body first to learn the subject).

No migration is needed: the index is rebuilt naturally as manifests are
(re)pushed, and an absent referrers directory simply yields an empty index.

## Consequences

- Attestation-bearing multi-arch images pull cleanly on Docker 29 / buildx.
- The referrers API is spec-compliant for third-party tools (cosign, oras, etc.)
  that push and query `subject`-linked artifacts.
- Note: buildx's *default* provenance is attached as
  `vnd.docker.reference.type=attestation-manifest` **children inside the manifest
  list**, not as separate `subject`-bearing manifests. Those do not populate the
  referrers index — and don't need to — but the client still probes the
  referrers endpoint during pull, so returning a valid empty index is what
  unblocks that flow. Explicit `subject`-based artifacts (oras / cosign style)
  are fully indexed and returned.

## Verification

Reproduced and fixed end-to-end against a local instance of the registry:

- **Unpatched binary**: `docker pull` of a `buildx --provenance=true --sbom=true`
  multi-arch image → `failed to decode referrers index: EOF`; the referrers
  endpoint returned `200` + empty body.
- **Patched binary**: same image pulls successfully and runs; the referrers
  endpoint returns a valid OCI index. A direct `subject`-bearing manifest `PUT`
  returns `OCI-Subject` and is returned by the referrers API with correct
  `artifactType`/`annotations`; `artifactType` filtering sets
  `OCI-Filters-Applied` and filters correctly.

Unit/integration coverage added in `internal/server/referrers_test.go`
(empty-index validity, subject indexing + `OCI-Subject`, config-mediaType
artifactType fallback, filtering match/miss, invalid-digest rejection).
