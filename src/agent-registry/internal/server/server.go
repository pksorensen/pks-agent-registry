package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

type Config struct {
	Addr       string
	AdminToken string
	Store      *store.Store

	// TrustedProxyCIDRs enables anonymous OCI read (GET/HEAD on /v2/*) when the request's
	// TCP source IP falls in one of these CIDRs. Writes always require auth. Empty disables
	// the bypass entirely. Typical value: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8".
	TrustedProxyCIDRs []*net.IPNet
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
// When TrustedProxyCIDRs is configured, the request's TCP source IP is checked first:
// requests originating from a trusted proxy/private network are allowed through without
// credentials (the auth boundary is then enforced by the proxy chain). Writes still go
// through requireOwnerWrite which calls this then enforces the {owner} segment match —
// but writes additionally validate r.BasicAuth() explicitly to keep push authenticated
// even when the proxy bypass is on.
func (s *Server) requireOwnerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Trusted-proxy bypass for reads (GET/HEAD only). Source must be in a configured CIDR.
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && s.isTrustedProxySource(r) {
			next(w, r)
			return
		}
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

// isTrustedProxySource reports whether the TCP source IP of r is in one of the
// configured trusted CIDRs. Only the raw RemoteAddr (TCP-level) is consulted —
// X-Forwarded-For is NOT trusted for this decision, since clients can spoof it.
func (s *Server) isTrustedProxySource(r *http.Request) bool {
	if len(s.cfg.TrustedProxyCIDRs) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s.cfg.TrustedProxyCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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
