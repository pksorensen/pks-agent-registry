package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

func (s *Server) handleV2Base(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	repos, err := s.cfg.Store.ListRepos()
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, err.Error())
		return
	}
	// Hide repositories the caller isn't allowed to pull (legacy/anonymous see all).
	owner := ownerFromContext(r.Context())
	visible := make([]string, 0, len(repos))
	for _, full := range repos {
		po, name, perr := store.ParseRepo(full)
		if perr != nil {
			continue
		}
		if owner.CanPull(po, name) {
			visible = append(visible, full)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"repositories": visible})
}

func (s *Server) handleTagsList(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	tags, err := s.cfg.Store.ListTags(owner, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name": owner + "/" + name,
		"tags": tags,
	})
}

// --- manifests ---

func (s *Server) handleManifestGet(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	body, info, err := s.cfg.Store.GetManifest(owner, name, ref)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, err.Error())
		return
	}
	mt := info.MediaType
	if mt == "" {
		mt = "application/vnd.oci.image.manifest.v1+json"
	}
	w.Header().Set("Content-Type", mt)
	w.Header().Set("Docker-Content-Digest", info.Digest)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}

func (s *Server) handleManifestPut(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	mediaType := r.Header.Get("Content-Type")
	if mediaType == "" {
		mediaType = "application/vnd.oci.image.manifest.v1+json"
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeManifestInvalid, err.Error())
		return
	}
	info, err := s.cfg.Store.PutManifest(owner, name, ref, mediaType, body)
	if errors.Is(err, store.ErrInvalidName) {
		writeError(w, http.StatusBadRequest, CodeNameInvalid, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeManifestInvalid, err.Error())
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/%s/manifests/%s", owner, name, info.Digest))
	w.Header().Set("Docker-Content-Digest", info.Digest)
	// OCI 1.1: when the pushed manifest carries a subject, echo it so the client
	// knows the referrers index was updated.
	if info.Subject != "" {
		w.Header().Set("OCI-Subject", info.Subject)
	}
	w.WriteHeader(http.StatusCreated)
}

// handleReferrers implements the OCI 1.1 referrers API:
//
//	GET /v2/<name>/referrers/<digest>[?artifactType=<type>]
//
// It always returns an OCI image index (never 404 for a valid digest) so a
// spec-compliant client never has to fall back to the tag schema. The index's
// `manifests` array holds a descriptor for every stored manifest whose
// `subject` points at <digest>; it is empty when there are none. When
// artifactType filtering is requested the OCI-Filters-Applied header is set.
func (s *Server) handleReferrers(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	digest := r.PathValue("digest")
	if !store.ValidDigest(digest) {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, "invalid digest")
		return
	}
	artifactType := r.URL.Query().Get("artifactType")
	refs, err := s.cfg.Store.ListReferrers(owner, name, digest, artifactType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, err.Error())
		return
	}
	index := ociReferrersIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests:     refs,
	}
	body, err := json.Marshal(index)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
	if artifactType != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// ociReferrersIndex is the OCI image index returned by the referrers API. The
// manifests array is always serialized (never null) thanks to the store
// returning a non-nil empty slice.
type ociReferrersIndex struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType"`
	Manifests     []store.Descriptor `json:"manifests"`
}

func (s *Server) handleManifestDelete(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	if err := s.cfg.Store.DeleteManifest(owner, name, ref); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// --- blobs ---

func (s *Server) handleBlobHead(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	exists, size, err := s.cfg.Store.HasBlob(digest)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob not found")
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Docker-Content-Digest", digest)
	// Advertise range support so clients that HEAD before GET (e.g. the ACR
	// server-side importer) know they may issue ranged reads.
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	rc, size, err := s.cfg.Store.OpenBlob(digest)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
		return
	}
	defer rc.Close()
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", "application/octet-stream")

	// Prefer http.ServeContent so Range requests are honoured with a proper
	// 206 Partial Content + Content-Range. `az acr import` copies blobs with
	// ranged GETs and fails ("want PartialContent: got OK") if the server
	// always returns 200 with the full body. The file store hands back an
	// *os.File, which is an io.ReadSeeker; fall back to a plain copy otherwise.
	if rs, ok := rc.(io.ReadSeeker); ok {
		// Empty name + octet-stream Content-Type already set → no sniffing;
		// zero modtime disables Last-Modified/If-Modified-Since handling.
		http.ServeContent(w, r, "", time.Time{}, rs)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleBlobDelete(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	if err := s.cfg.Store.DeleteBlob(digest); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob not found")
		return
	} else if err != nil {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// --- blob uploads ---

func (s *Server) handleUploadStart(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	digest := r.URL.Query().Get("digest")
	id, err := s.cfg.Store.StartUpload()
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, err.Error())
		return
	}

	// Monolithic POST: body present and ?digest=... → write body then finalize.
	if digest != "" && r.ContentLength != 0 {
		if _, err := s.cfg.Store.AppendUpload(id, r.Body); err != nil {
			_ = s.cfg.Store.AbortUpload(id)
			writeError(w, http.StatusInternalServerError, CodeBlobUploadInvalid, err.Error())
			return
		}
		if err := s.cfg.Store.FinalizeUpload(id, digest); err != nil {
			_ = s.cfg.Store.AbortUpload(id)
			if errors.Is(err, store.ErrDigestMismatch) {
				writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, CodeBlobUploadInvalid, err.Error())
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/%s/blobs/%s", owner, name, digest))
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/%s/blobs/uploads/%s", owner, name, id))
	w.Header().Set("Range", "0-0")
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleUploadPatch(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	size, err := s.cfg.Store.AppendUpload(id, r.Body)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeBlobUploadInvalid, err.Error())
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/%s/blobs/uploads/%s", owner, name, id))
	w.Header().Set("Range", fmt.Sprintf("0-%d", size-1))
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleUploadPut(w http.ResponseWriter, r *http.Request) {
	owner, name, ok := repoParts(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, "digest query parameter required")
		return
	}
	if r.ContentLength > 0 {
		if _, err := s.cfg.Store.AppendUpload(id, r.Body); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found")
				return
			}
			writeError(w, http.StatusInternalServerError, CodeBlobUploadInvalid, err.Error())
			return
		}
	}
	if err := s.cfg.Store.FinalizeUpload(id, digest); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found")
			return
		}
		if errors.Is(err, store.ErrDigestMismatch) {
			writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, CodeBlobUploadInvalid, err.Error())
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/%s/blobs/%s", owner, name, digest))
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleUploadAbort(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Store.AbortUpload(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "upload not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, CodeBlobUploadInvalid, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// repoParts extracts {owner}/{name} from the request and validates them.
func repoParts(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	owner := r.PathValue("owner")
	name := r.PathValue("name")
	if !store.ValidName(owner) || !store.ValidName(name) {
		writeError(w, http.StatusBadRequest, CodeNameInvalid, "invalid repository name")
		return "", "", false
	}
	return owner, name, true
}
