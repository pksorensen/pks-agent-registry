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

	m.HandleFunc("GET /v2/{owner}/{name}/tags/list", s.requireOwnerRead(s.handleTagsList))

	m.HandleFunc("GET /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerRead(s.handleManifestGet))
	m.HandleFunc("HEAD /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerRead(s.handleManifestGet))
	m.HandleFunc("PUT /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerWrite(s.handleManifestPut))
	m.HandleFunc("DELETE /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerWrite(s.handleManifestDelete))

	m.HandleFunc("GET /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerRead(s.handleBlobGet))
	m.HandleFunc("HEAD /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerRead(s.handleBlobHead))
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
	m.HandleFunc("PUT /_mgmt/owners/{name}/permissions", s.requireAdmin(s.handleMgmtOwnerPermissions))
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
		owner, ok := s.basicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}
		r = r.WithContext(contextWithOwner(r.Context(), owner))
		next(w, r)
	}
}

// requireOwnerRead enforces per-repository pull scopes on top of authentication.
// Owners with no Permissions block (legacy) and anonymous trusted-proxy reads
// retain full read access; scoped owners are limited to their own namespace plus
// matching PullScopes.
func (s *Server) requireOwnerRead(next http.HandlerFunc) http.HandlerFunc {
	return s.requireOwnerAuth(func(w http.ResponseWriter, r *http.Request) {
		owner := ownerFromContext(r.Context())
		if !owner.CanPull(r.PathValue("owner"), r.PathValue("name")) {
			writeError(w, http.StatusForbidden, CodeDenied, "not authorized to pull this repository")
			return
		}
		next(w, r)
	})
}

// isTrustedProxySource reports whether the request originated from a *trusted internal
// network*, not just from the proxy itself. The check has two parts:
//
//  1. The TCP source IP (r.RemoteAddr) must be in TrustedProxyCIDRs — this confirms the
//     immediate sender is the reverse proxy we expect.
//  2. The LAST entry of X-Forwarded-For must also be in TrustedProxyCIDRs — this is the
//     IP that the proxy itself observed as its caller. The well-known reverse proxies
//     (Traefik, Caddy, nginx) APPEND to XFF rather than trust client-supplied values, so
//     the last hop is set by the proxy and reflects the real upstream. For an external
//     internet client, the last XFF entry is their public IP (not in TrustedProxyCIDRs)
//     → bypass denied. For a docker-host pull that loops through the bridge to the proxy,
//     the source IP at the proxy is private (a docker0 / bridge gateway) → bypass allowed.
//
// Combining (1) and (2) means: only requests that were both delivered by the trusted proxy
// AND originated from a trusted upstream get the anonymous-read pass.
func (s *Server) isTrustedProxySource(r *http.Request) bool {
	if len(s.cfg.TrustedProxyCIDRs) == 0 {
		return false
	}
	// (1) TCP source is the proxy itself.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	tcpIP := net.ParseIP(host)
	if tcpIP == nil || !cidrContains(s.cfg.TrustedProxyCIDRs, tcpIP) {
		return false
	}
	// (2) The proxy-appended last XFF entry is also private. Missing/empty XFF means the
	// request didn't traverse a proxy — reject (a direct connection on the bridge with no
	// proxy is unexpected; the operator should narrow the CIDR if that's intentional).
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return false
	}
	// XFF is "client, proxy1, proxy2, ..." — Traefik/Caddy/nginx append the immediate
	// previous-hop IP as the last entry. We want that last entry.
	parts := strings.Split(xff, ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	upstreamIP := net.ParseIP(last)
	if upstreamIP == nil {
		return false
	}
	return cidrContains(s.cfg.TrustedProxyCIDRs, upstreamIP)
}

func cidrContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
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
		owner := ownerFromContext(r.Context())
		if owner == nil {
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}
		pathOwner := r.PathValue("owner")
		if pathOwner != "" && pathOwner != owner.Name {
			writeError(w, http.StatusForbidden, CodeDenied, "cannot write to another owner's namespace")
			return
		}
		if !owner.CanPush() {
			writeError(w, http.StatusForbidden, CodeDenied, "this credential is not permitted to push")
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

func (s *Server) basicAuth(r *http.Request) (*store.Owner, bool) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}
	if !s.cfg.Store.CheckPassword(user, pass) {
		return nil, false
	}
	o, err := s.cfg.Store.GetOwner(user)
	if err != nil {
		return nil, false
	}
	return o, true
}
