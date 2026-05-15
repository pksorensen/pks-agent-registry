package server

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

type Config struct {
	Addr       string
	AdminToken string
	Store      *store.Store
}

type Server struct {
	cfg Config
	mux *http.ServeMux
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.cfg.Addr, s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	m := s.mux

	// OCI v2 — base + catalog + per-repo endpoints.
	m.HandleFunc("GET /v2/", s.requireOwnerAuth(s.handleV2Base))
	m.HandleFunc("GET /v2/_catalog", s.requireOwnerAuth(s.handleCatalog))

	m.HandleFunc("GET /v2/{owner}/{name}/tags/list", s.requireOwnerAuth(s.handleTagsList))

	m.HandleFunc("GET /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerAuth(s.handleManifestGet))
	m.HandleFunc("HEAD /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerAuth(s.handleManifestGet))
	m.HandleFunc("PUT /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerWrite(s.handleManifestPut))
	m.HandleFunc("DELETE /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerWrite(s.handleManifestDelete))

	m.HandleFunc("GET /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerAuth(s.handleBlobGet))
	m.HandleFunc("HEAD /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerAuth(s.handleBlobHead))
	m.HandleFunc("DELETE /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerWrite(s.handleBlobDelete))

	m.HandleFunc("POST /v2/{owner}/{name}/blobs/uploads/", s.requireOwnerWrite(s.handleUploadStart))
	m.HandleFunc("PATCH /v2/{owner}/{name}/blobs/uploads/{id}", s.requireOwnerWrite(s.handleUploadPatch))
	m.HandleFunc("PUT /v2/{owner}/{name}/blobs/uploads/{id}", s.requireOwnerWrite(s.handleUploadPut))
	m.HandleFunc("DELETE /v2/{owner}/{name}/blobs/uploads/{id}", s.requireOwnerWrite(s.handleUploadAbort))

	// Management API — admin-token gated, designed for a future UI.
	m.HandleFunc("GET /_mgmt/health", s.handleHealth)
	m.HandleFunc("GET /_mgmt/owners", s.requireAdmin(s.handleMgmtOwnersList))
	m.HandleFunc("POST /_mgmt/owners", s.requireAdmin(s.handleMgmtOwnerCreate))
	m.HandleFunc("GET /_mgmt/owners/{name}", s.requireAdmin(s.handleMgmtOwnerGet))
	m.HandleFunc("DELETE /_mgmt/owners/{name}", s.requireAdmin(s.handleMgmtOwnerDelete))
	m.HandleFunc("PUT /_mgmt/owners/{name}/password", s.requireAdmin(s.handleMgmtOwnerPassword))
	m.HandleFunc("GET /_mgmt/repos", s.requireAdmin(s.handleMgmtReposList))
	m.HandleFunc("DELETE /_mgmt/repos/{owner}/{name}", s.requireAdmin(s.handleMgmtRepoDelete))
	m.HandleFunc("GET /_mgmt/repos/{owner}/{name}/tags", s.requireAdmin(s.handleMgmtTagsList))
	m.HandleFunc("DELETE /_mgmt/repos/{owner}/{name}/tags/{tag}", s.requireAdmin(s.handleMgmtTagDelete))
	m.HandleFunc("POST /_mgmt/gc", s.requireAdmin(s.handleMgmtGC))
}

// --- middleware ---

type ctxKey int

const ctxKeyAuthUser ctxKey = 1

// requireOwnerAuth lets any valid owner credential through (read-only access).
func (s *Server) requireOwnerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.basicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}
		r = r.WithContext(contextWithUser(r.Context(), user))
		next(w, r)
	}
}

// requireOwnerWrite additionally enforces that the path's {owner} segment
// matches the authenticated user.
func (s *Server) requireOwnerWrite(next http.HandlerFunc) http.HandlerFunc {
	return s.requireOwnerAuth(func(w http.ResponseWriter, r *http.Request) {
		user := userFromContext(r.Context())
		owner := r.PathValue("owner")
		if owner != "" && owner != user {
			writeError(w, http.StatusForbidden, CodeDenied, "cannot write to another owner's namespace")
			return
		}
		next(w, r)
	})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			http.Error(w, "management API disabled (REGISTRY_ADMIN_TOKEN unset)", http.StatusServiceUnavailable)
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="registry-mgmt"`)
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		got := strings.TrimPrefix(h, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AdminToken)) != 1 {
			http.Error(w, "invalid admin token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) basicAuth(r *http.Request) (string, bool) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return "", false
	}
	if !s.cfg.Store.CheckPassword(user, pass) {
		return "", false
	}
	return user, true
}
