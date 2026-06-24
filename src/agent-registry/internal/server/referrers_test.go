package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// putManifest pushes a manifest body under a tag/digest ref with owner creds.
func putManifest(t *testing.T, s *Server, owner, name, ref, mediaType string, body []byte, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v2/%s/%s/manifests/%s", owner, name, ref), strings.NewReader(string(body)))
	req.Header.Set("Content-Type", mediaType)
	req.SetBasicAuth(user, pass)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func seedOwner(t *testing.T, st *store.Store, name string) {
	t.Helper()
	if _, err := st.PutOwner(name, "pw"); err != nil {
		t.Fatalf("PutOwner %s: %v", name, err)
	}
}

// TestReferrersEmptyReturnsValidIndex is the core regression test: a digest with
// no referrers must return a 200 with a well-formed OCI image index (empty
// manifests array), NOT a 404 or empty body that makes a Docker client fail to
// decode the referrers index.
func TestReferrersEmptyReturnsValidIndex(t *testing.T) {
	s, st := newPermServer(t)
	seedOwner(t, st, "agentics")

	// Push a plain image manifest (the subject).
	img := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"layers":[]}`)
	if rec := putManifest(t, s, "agentics", "app", "latest", "application/vnd.oci.image.manifest.v1+json", img, "agentics", "pw"); rec.Code != http.StatusCreated {
		t.Fatalf("push image: got %d body=%s", rec.Code, rec.Body.String())
	}
	subj := digestOf(img)

	rec := doAuth(t, s, http.MethodGet, "/v2/agentics/app/referrers/"+subj, "agentics", "pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("referrers (empty): got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.oci.image.index.v1+json" {
		t.Fatalf("referrers content-type = %q, want oci index", ct)
	}
	var idx ociReferrersIndex
	if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode referrers index: %v (body=%s)", err, rec.Body.String())
	}
	if idx.MediaType != "application/vnd.oci.image.index.v1+json" {
		t.Fatalf("index mediaType = %q", idx.MediaType)
	}
	if idx.Manifests == nil {
		t.Fatalf("manifests must serialize as [] not null; body=%s", rec.Body.String())
	}
	if len(idx.Manifests) != 0 {
		t.Fatalf("expected 0 referrers, got %d", len(idx.Manifests))
	}
}

// TestReferrersSubjectIndexedAndReturned pushes an attestation-style manifest
// carrying a `subject` and verifies it is returned by the referrers API, that
// the OCI-Subject header is echoed on PUT, and that artifactType filtering works.
func TestReferrersSubjectIndexedAndReturned(t *testing.T) {
	s, st := newPermServer(t)
	seedOwner(t, st, "agentics")

	img := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"layers":[]}`)
	if rec := putManifest(t, s, "agentics", "app", "latest", "application/vnd.oci.image.manifest.v1+json", img, "agentics", "pw"); rec.Code != http.StatusCreated {
		t.Fatalf("push image: got %d body=%s", rec.Code, rec.Body.String())
	}
	subj := digestOf(img)

	// An attestation manifest referencing the image via `subject`.
	att := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.dev.cosign.artifact.sig.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"},"layers":[],"subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d},"annotations":{"org.opencontainers.image.created":"now"}}`, subj, len(img)))
	attDigest := digestOf(att)
	recPut := putManifest(t, s, "agentics", "app", attDigest, "application/vnd.oci.image.manifest.v1+json", att, "agentics", "pw")
	if recPut.Code != http.StatusCreated {
		t.Fatalf("push attestation: got %d body=%s", recPut.Code, recPut.Body.String())
	}
	if got := recPut.Header().Get("OCI-Subject"); got != subj {
		t.Fatalf("OCI-Subject = %q, want %q", got, subj)
	}

	// Unfiltered referrers must contain the attestation.
	rec := doAuth(t, s, http.MethodGet, "/v2/agentics/app/referrers/"+subj, "agentics", "pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("referrers: got %d body=%s", rec.Code, rec.Body.String())
	}
	var idx ociReferrersIndex
	if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("expected 1 referrer, got %d (%s)", len(idx.Manifests), rec.Body.String())
	}
	d := idx.Manifests[0]
	if d.Digest != attDigest {
		t.Fatalf("referrer digest = %q, want %q", d.Digest, attDigest)
	}
	if d.ArtifactType != "application/vnd.dev.cosign.artifact.sig.v1+json" {
		t.Fatalf("artifactType = %q", d.ArtifactType)
	}
	if d.Annotations["org.opencontainers.image.created"] != "now" {
		t.Fatalf("annotations not carried: %#v", d.Annotations)
	}

	// Matching artifactType filter returns it + sets OCI-Filters-Applied.
	rec = doAuth(t, s, http.MethodGet, "/v2/agentics/app/referrers/"+subj+"?artifactType="+url.QueryEscape("application/vnd.dev.cosign.artifact.sig.v1+json"), "agentics", "pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered referrers: %d", rec.Code)
	}
	if rec.Header().Get("OCI-Filters-Applied") != "artifactType" {
		t.Fatalf("OCI-Filters-Applied not set")
	}
	idx = ociReferrersIndex{}
	_ = json.Unmarshal(rec.Body.Bytes(), &idx)
	if len(idx.Manifests) != 1 {
		t.Fatalf("filtered (match): expected 1, got %d", len(idx.Manifests))
	}

	// Non-matching artifactType filter returns an empty (but valid) index.
	rec = doAuth(t, s, http.MethodGet, "/v2/agentics/app/referrers/"+subj+"?artifactType=application/other", "agentics", "pw")
	idx = ociReferrersIndex{}
	if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode filtered-miss: %v", err)
	}
	if idx.Manifests == nil || len(idx.Manifests) != 0 {
		t.Fatalf("filtered (miss): expected empty non-nil, got %#v", idx.Manifests)
	}
}

// TestReferrersConfigMediaTypeFallback verifies artifactType falls back to the
// config descriptor's mediaType when no top-level artifactType is present
// (the shape buildx provenance manifests use).
func TestReferrersConfigMediaTypeFallback(t *testing.T) {
	s, st := newPermServer(t)
	seedOwner(t, st, "agentics")

	img := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,"digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333"},"layers":[]}`)
	putManifest(t, s, "agentics", "app", "latest", "application/vnd.oci.image.manifest.v1+json", img, "agentics", "pw")
	subj := digestOf(img)

	att := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.in-toto+json","size":2,"digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444"},"layers":[],"subject":{"digest":%q,"size":%d}}`, subj, len(img)))
	attDigest := digestOf(att)
	putManifest(t, s, "agentics", "app", attDigest, "application/vnd.oci.image.manifest.v1+json", att, "agentics", "pw")

	rec := doAuth(t, s, http.MethodGet, "/v2/agentics/app/referrers/"+subj, "agentics", "pw")
	var idx ociReferrersIndex
	_ = json.Unmarshal(rec.Body.Bytes(), &idx)
	if len(idx.Manifests) != 1 || idx.Manifests[0].ArtifactType != "application/vnd.in-toto+json" {
		t.Fatalf("config-mediaType fallback failed: %s", rec.Body.String())
	}
}

// TestReferrersInvalidDigest rejects a non-digest reference.
func TestReferrersInvalidDigest(t *testing.T) {
	s, st := newPermServer(t)
	seedOwner(t, st, "agentics")
	rec := doAuth(t, s, http.MethodGet, "/v2/agentics/app/referrers/notadigest", "agentics", "pw")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid digest: got %d, want 400", rec.Code)
	}
}
