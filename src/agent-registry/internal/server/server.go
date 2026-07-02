package server

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/pksorensen/pks-agent-registry/internal/ghoidc"
	"github.com/pksorensen/pks-agent-registry/internal/store"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

type Config struct {
	Addr       string
	AdminToken string
	Store      *store.Store

	// TrustedProxyCIDRs enables anonymous OCI read (GET/HEAD on /v2/*) when the request's
	// TCP source IP falls in one of these CIDRs. Writes always require auth. Empty disables
	// the bypass entirely. Typical value: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8".
	TrustedProxyCIDRs []*net.IPNet

	// PublicURL is the externally reachable base URL of the registry
	// (e.g. https://registry.agentics.dk). Setting it (together with TokenKey)
	// arms the Distribution token service: /v2/ 401s additionally advertise
	// `Bearer realm="<PublicURL>/token"` and the /token endpoint mints registry
	// access tokens. Its hostname is both the token "service" and the required
	// GitHub OIDC audience. Empty keeps the pre-token behavior (Basic only).
	PublicURL string
	// TokenKey signs registry access tokens (ES256); TokenKid identifies it.
	TokenKey *ecdsa.PrivateKey
	TokenKid string
	// OIDC validates GitHub Actions tokens against federated trust bindings.
	OIDC *ghoidc.Validator
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
	// {$} anchors this to the EXACT /v2/ path (the OCI version-check ping). A
	// bare "GET /v2/" is a subtree match that swallows every unmatched /v2/...
	// GET and answers 200-empty instead of 404 — which silently broke clients
	// probing endpoints we don't serve (this is what produced the referrers
	// "decode index: EOF"). With the anchor, unmatched /v2/... GETs 404 cleanly.
	m.HandleFunc("GET /v2/{$}", s.requireOwnerAuth(s.handleV2Base))
	m.HandleFunc("GET /v2/_catalog", s.requireOwnerAuth(s.handleCatalog))

	m.HandleFunc("GET /v2/{owner}/{name}/tags/list", s.requireOwnerRead(s.handleTagsList))

	m.HandleFunc("GET /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerRead(s.handleManifestGet))
	m.HandleFunc("HEAD /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerRead(s.handleManifestGet))
	m.HandleFunc("PUT /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerWrite(s.handleManifestPut))
	m.HandleFunc("DELETE /v2/{owner}/{name}/manifests/{ref}", s.requireOwnerWrite(s.handleManifestDelete))

	m.HandleFunc("GET /v2/{owner}/{name}/referrers/{digest}", s.requireOwnerRead(s.handleReferrers))

	m.HandleFunc("GET /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerRead(s.handleBlobGet))
	m.HandleFunc("HEAD /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerRead(s.handleBlobHead))
	m.HandleFunc("DELETE /v2/{owner}/{name}/blobs/{digest}", s.requireOwnerWrite(s.handleBlobDelete))

	m.HandleFunc("POST /v2/{owner}/{name}/blobs/uploads/", s.requireOwnerWrite(s.handleUploadStart))
	m.HandleFunc("PATCH /v2/{owner}/{name}/blobs/uploads/{id}", s.requireOwnerWrite(s.handleUploadPatch))
	m.HandleFunc("PUT /v2/{owner}/{name}/blobs/uploads/{id}", s.requireOwnerWrite(s.handleUploadPut))
	m.HandleFunc("DELETE /v2/{owner}/{name}/blobs/uploads/{id}", s.requireOwnerWrite(s.handleUploadAbort))

	// Distribution token service (ADR 0003). Registered unconditionally; the
	// handler answers 501 until PublicURL/TokenKey arm the feature.
	m.HandleFunc("GET /token", s.handleToken)

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

	// Federated trust bindings (ADR 0003).
	m.HandleFunc("GET /_mgmt/federation", s.requireAdmin(s.handleMgmtFederationList))
	m.HandleFunc("POST /_mgmt/federation", s.requireAdmin(s.handleMgmtFederationCreate))
	m.HandleFunc("GET /_mgmt/federation/{id}", s.requireAdmin(s.handleMgmtFederationGet))
	m.HandleFunc("DELETE /_mgmt/federation/{id}", s.requireAdmin(s.handleMgmtFederationDelete))
}

// --- middleware ---

type ctxKey int

const (
	ctxKeyAuthUser   ctxKey = 1
	ctxKeyAuthBearer ctxKey = 2
)

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
		// Registry-minted bearer tokens (Distribution token flow, ADR 0003).
		// The /_mgmt admin token is a different route tree; any Bearer here is
		// expected to be one of ours.
		if raw, err := bearerToken(r); err == nil && s.tokenAuthEnabled() {
			owner, err := s.bearerPrincipal(raw)
			if err != nil {
				log.Printf("auth failed: reason=bad-bearer-token err=%q ip=%s method=%s path=%s", err, clientIP(r), r.Method, r.URL.Path)
				s.writeChallenges(w, "")
				writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
				return
			}
			ctx := contextWithOwner(r.Context(), owner)
			ctx = contextWithBearer(ctx)
			next(w, r.WithContext(ctx))
			return
		}
		owner, reason := s.basicAuth(r)
		if owner == nil {
			log.Printf("auth failed: reason=%s ip=%s method=%s path=%s", reason, clientIP(r), r.Method, r.URL.Path)
			s.writeChallenges(w, "")
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}
		r = r.WithContext(contextWithOwner(r.Context(), owner))
		next(w, r)
	}
}

// writeChallenges emits the WWW-Authenticate challenge(s) for a /v2/ 401.
// With the token service armed, both Bearer (preferred by docker/oras/crane)
// and Basic (legacy clients, raw curl) are advertised; the Bearer challenge
// carries the needed scope on insufficient-scope denials so conforming
// clients transparently re-fetch a correctly scoped token.
func (s *Server) writeChallenges(w http.ResponseWriter, scope string) {
	if s.tokenAuthEnabled() {
		c := fmt.Sprintf("Bearer realm=%q,service=%q", s.cfg.PublicURL+"/token", s.service())
		if scope != "" {
			c += fmt.Sprintf(",scope=%q,error=%q", scope, "insufficient_scope")
		}
		w.Header().Add("WWW-Authenticate", c)
	}
	w.Header().Add("WWW-Authenticate", `Basic realm="registry"`)
}

// requireOwnerRead enforces per-repository pull scopes on top of authentication.
// Owners with no Permissions block (legacy) and anonymous trusted-proxy reads
// retain full read access; scoped owners are limited to their own namespace plus
// matching PullScopes.
func (s *Server) requireOwnerRead(next http.HandlerFunc) http.HandlerFunc {
	return s.requireOwnerAuth(func(w http.ResponseWriter, r *http.Request) {
		owner := ownerFromContext(r.Context())
		if !owner.CanPull(r.PathValue("owner"), r.PathValue("name")) {
			log.Printf("pull denied: user=%q repo=%s/%s ip=%s", owner.Name, r.PathValue("owner"), r.PathValue("name"), clientIP(r))
			// Bearer principals get a 401 with the needed scope so token-flow
			// clients re-fetch a correctly scoped token; Basic keeps the 403.
			if isBearerAuth(r.Context()) {
				s.writeChallenges(w, fmt.Sprintf("repository:%s/%s:pull", r.PathValue("owner"), r.PathValue("name")))
				writeError(w, http.StatusUnauthorized, CodeUnauthorized, "insufficient scope for this repository")
				return
			}
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
			log.Printf("write denied: user=%q reason=namespace-mismatch target=%s ip=%s path=%s", owner.Name, pathOwner, clientIP(r), r.URL.Path)
			s.denyWrite(w, r, "cannot write to another owner's namespace")
			return
		}
		if !owner.CanPush() {
			log.Printf("write denied: user=%q reason=pull-only-credential ip=%s path=%s", owner.Name, clientIP(r), r.URL.Path)
			s.denyWrite(w, r, "this credential is not permitted to push")
			return
		}
		next(w, r)
	})
}

// denyWrite rejects a write: 401 + scoped Bearer challenge for token-flow
// clients (spec-conform re-auth), 403 for Basic principals (today's behavior).
func (s *Server) denyWrite(w http.ResponseWriter, r *http.Request, msg string) {
	if isBearerAuth(r.Context()) {
		if o, n := r.PathValue("owner"), r.PathValue("name"); o != "" && n != "" {
			s.writeChallenges(w, fmt.Sprintf("repository:%s/%s:pull,push", o, n))
		} else {
			s.writeChallenges(w, "")
		}
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, msg)
		return
	}
	writeError(w, http.StatusForbidden, CodeDenied, msg)
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
			log.Printf("auth failed: reason=bad-admin-token ip=%s path=%s", clientIP(r), r.URL.Path)
			http.Error(w, "invalid admin token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// basicAuth authenticates the request's Basic credentials. On failure it returns a
// nil owner plus a log-safe reason string (never the password itself). The reason
// includes a whitespace hint because trailing newlines from copy-paste are the most
// common cause of "the password is right but login fails" support cases.
func (s *Server) basicAuth(r *http.Request) (*store.Owner, string) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, "no-credentials"
	}
	// A JWT-shaped password is a GitHub OIDC credential (federated trust
	// binding), not an owner password — belt-and-braces for clients that
	// ignore the Bearer challenge and replay Basic on /v2/ directly.
	if s.tokenAuthEnabled() && s.cfg.OIDC != nil && token.LooksLikeJWT(pass) {
		p, ok := s.resolveFederated(pass)
		if !ok {
			return nil, "federated-token-rejected"
		}
		return p.asOwner(), ""
	}
	if _, err := s.cfg.Store.GetOwner(user); err != nil {
		return nil, "unknown-owner user=" + strconv.Quote(user) + whitespaceHint(user, pass)
	}
	if !s.cfg.Store.CheckPassword(user, pass) {
		return nil, "bad-password user=" + strconv.Quote(user) + whitespaceHint(user, pass)
	}
	o, err := s.cfg.Store.GetOwner(user)
	if err != nil {
		return nil, "owner-load-error user=" + strconv.Quote(user)
	}
	return o, ""
}

// whitespaceHint flags credentials carrying leading/trailing whitespace (typically a
// trailing newline pasted into a secret store) without revealing their contents.
func whitespaceHint(user, pass string) string {
	var hints []string
	if user != strings.TrimSpace(user) {
		hints = append(hints, "user-has-whitespace")
	}
	if pass != strings.TrimSpace(pass) {
		hints = append(hints, "password-has-whitespace")
	}
	if len(hints) == 0 {
		return ""
	}
	return " hint=" + strings.Join(hints, ",")
}

// clientIP prefers the first X-Forwarded-For entry (the original client as seen by the
// reverse proxy) and falls back to the TCP peer address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return r.RemoteAddr
}
