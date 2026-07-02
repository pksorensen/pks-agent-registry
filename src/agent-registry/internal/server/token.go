package server

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/store"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

// tokenIssuer is the iss claim of registry-minted access tokens.
const tokenIssuer = "agent-registry"

// tokenAuthEnabled reports whether the Distribution token service is armed
// (requires REGISTRY_PUBLIC_URL so realm/service/audience are known).
func (s *Server) tokenAuthEnabled() bool {
	return s.cfg.PublicURL != "" && s.cfg.TokenKey != nil
}

// service is the Distribution "service" identifier: the registry hostname.
func (s *Server) service() string {
	u, err := url.Parse(s.cfg.PublicURL)
	if err != nil || u.Host == "" {
		return s.cfg.PublicURL
	}
	return u.Host
}

// principal is a resolved credential: the identity plus the permissions it
// carries. ownerNS is the registry namespace it acts as ("" for pull-only
// federated identities); perms is nil only for legacy full-access owners.
type principal struct {
	sub     string
	ownerNS string
	perms   *store.Permissions
}

// asOwner projects the principal onto the store.Owner shape the existing
// middleware and CanPull/CanPush logic operate on.
func (p *principal) asOwner() *store.Owner {
	return &store.Owner{Name: p.ownerNS, Permissions: p.perms}
}

// resolvePrincipal validates basic-auth-carried credentials. The password is
// either a static owner password (bcrypt) or a GitHub Actions OIDC JWT that
// must match a trust binding; the username is ignored for OIDC credentials.
func (s *Server) resolvePrincipal(user, pass string) (*principal, bool) {
	if s.tokenAuthEnabled() && s.cfg.OIDC != nil && token.LooksLikeJWT(pass) {
		return s.resolveFederated(pass)
	}
	if !s.cfg.Store.CheckPassword(user, pass) {
		return nil, false
	}
	o, err := s.cfg.Store.GetOwner(user)
	if err != nil {
		return nil, false
	}
	return &principal{sub: o.Name, ownerNS: o.Name, perms: o.Permissions}, true
}

func (s *Server) resolveFederated(rawJWT string) (*principal, bool) {
	claims, err := s.cfg.OIDC.Validate(rawJWT, time.Now())
	if err != nil {
		log.Printf("federation: token rejected: %v", err)
		return nil, false
	}
	bindings, err := s.cfg.Store.ListTrustBindings()
	if err != nil {
		log.Printf("federation: list bindings: %v", err)
		return nil, false
	}
	for _, b := range bindings {
		if !b.Matches(claims.Repository, claims.RepositoryID, claims.RepositoryOwnerID, claims.Environment) {
			continue
		}
		if !b.Pinned() {
			if err := s.cfg.Store.PinTrustBinding(b.ID, claims.RepositoryID, claims.RepositoryOwnerID); err != nil {
				log.Printf("federation: pin binding %s: %v", b.ID, err)
			} else {
				log.Printf("federation: binding %s pinned to repository_id=%s owner_id=%s (%s)",
					b.ID, claims.RepositoryID, claims.RepositoryOwnerID, claims.Repository)
			}
		}
		perms := b.Permissions
		if perms == nil {
			// CreateTrustBinding forbids this; guard anyway so a hand-edited
			// binding file can never grant legacy full access.
			perms = &store.Permissions{}
		}
		log.Printf("federation: authenticated %s (binding %s, env=%q)", b.PrincipalName(), b.ID, claims.Environment)
		return &principal{sub: b.PrincipalName(), ownerNS: b.Owner, perms: perms}, true
	}
	log.Printf("federation: no trust binding matches repository=%q id=%q env=%q", claims.Repository, claims.RepositoryID, claims.Environment)
	return nil, false
}

// parseScopes parses repeated Distribution scope parameters:
// "repository:<owner>/<name>:pull,push". Unknown resource types and unknown
// actions are ignored (the spec grants nothing for them rather than erroring).
func parseScopes(r *http.Request) []token.Access {
	var out []token.Access
	for _, raw := range r.URL.Query()["scope"] {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 || parts[0] != "repository" {
			continue
		}
		rest := parts[1]
		idx := strings.LastIndex(rest, ":")
		if idx <= 0 || idx == len(rest)-1 {
			continue
		}
		name := rest[:idx]
		var actions []string
		for _, a := range strings.Split(rest[idx+1:], ",") {
			if a == "pull" || a == "push" {
				actions = append(actions, a)
			}
		}
		if len(actions) == 0 {
			continue
		}
		out = append(out, token.Access{Type: "repository", Name: name, Actions: actions})
	}
	return out
}

// grantAccess intersects the requested scopes with what the principal's
// permissions allow. Disallowed actions are silently dropped per the token
// spec — the client receives a token with reduced access and the data plane
// rejects anything beyond it.
func grantAccess(p *principal, requested []token.Access) []token.Access {
	pseudo := p.asOwner()
	granted := make([]token.Access, 0, len(requested))
	for _, req := range requested {
		owner, name, err := store.ParseRepo(req.Name)
		if err != nil {
			continue
		}
		var actions []string
		for _, a := range req.Actions {
			switch a {
			case "pull":
				if pseudo.CanPull(owner, name) {
					actions = append(actions, a)
				}
			case "push":
				if owner == p.ownerNS && pseudo.CanPush() {
					actions = append(actions, a)
				}
			}
		}
		if len(actions) > 0 {
			granted = append(granted, token.Access{Type: "repository", Name: req.Name, Actions: actions})
		}
	}
	return granted
}

// handleToken is the Distribution token endpoint (WWW-Authenticate Bearer
// realm). It authenticates basic-auth-carried credentials — static owner
// passwords or GitHub OIDC JWTs — and mints a registry-signed access token.
// A scope-less request is the `docker login` probe and still returns a token.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.tokenAuthEnabled() {
		writeError(w, http.StatusNotImplemented, CodeUnsupported, "token auth is not configured (REGISTRY_PUBLIC_URL unset)")
		return
	}
	if svc := r.URL.Query().Get("service"); svc != "" && svc != s.service() {
		writeError(w, http.StatusBadRequest, CodeDenied, "unknown service")
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry-token"`)
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
		return
	}
	p, ok := s.resolvePrincipal(user, pass)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry-token"`)
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid credentials")
		return
	}

	granted := grantAccess(p, parseScopes(r))
	jwt, expiresIn, issuedAt, err := token.Mint(s.cfg.TokenKey, s.cfg.TokenKid, tokenIssuer, s.service(), p.sub, p.ownerNS, granted, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeUnsupported, "token minting failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        jwt,
		"access_token": jwt,
		"expires_in":   expiresIn,
		"issued_at":    issuedAt.Format(time.RFC3339),
	})
}

// bearerPrincipal verifies a registry-minted bearer token from the data plane
// and projects it onto the Owner shape. The token's access claims are
// enforced statelessly (no binding re-lookup; revocation latency is bounded
// by the token TTL — ADR 0003).
func (s *Server) bearerPrincipal(raw string) (*store.Owner, error) {
	claims, err := token.Verify(raw, &s.cfg.TokenKey.PublicKey, tokenIssuer, s.service(), time.Now())
	if err != nil {
		return nil, err
	}
	perms := &store.Permissions{}
	for _, a := range claims.Access {
		if a.Type != "repository" {
			continue
		}
		for _, action := range a.Actions {
			switch action {
			case "pull":
				perms.PullScopes = append(perms.PullScopes, a.Name)
			case "push":
				perms.Push = true
			}
		}
	}
	name := claims.Owner
	if name == "" {
		name = claims.Sub
	}
	return &store.Owner{Name: name, Permissions: perms}, nil
}

var errNoBearer = errors.New("no bearer token")

// bearerToken extracts a Bearer credential from the Authorization header.
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", errNoBearer
	}
	return strings.TrimPrefix(h, "Bearer "), nil
}
