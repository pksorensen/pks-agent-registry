package server

import (
	"net/http"
	"strings"
)

// wellKnownPRM is the RFC 9728 OAuth 2.0 Protected Resource Metadata path.
// The registry is the resource; the document tells any client which
// authorization server to go to. It is what makes `agent-registry login`
// portable: point the binary at someone else's registry and it discovers
// their issuer rather than assuming ours.
const wellKnownPRM = "/.well-known/oauth-protected-resource"

// protectedResourceMetadata is the RFC 9728 document, plus one extension.
//
// ClientID is that extension. RFC 9728 has no field for it, and dynamic client
// registration (RFC 7591) is not something the authorization servers people
// actually run have adopted, so a public client id has to reach the CLI
// somehow. Naming it here keeps the CLI free of hardcoded per-registry
// knowledge; it is documented as ours, not implied to be standard.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`

	// ClientID is the public OAuth client the CLI should authenticate as.
	// Non-standard; see above.
	ClientID string `json:"client_id,omitempty"`

	// Audience is the value this registry requires in a token's `aud`.
	// Non-standard, and usually the same as Resource's host — but not always:
	// a registry reached at localhost or behind a proxy still enforces the
	// audience its realm was told to stamp. Saying so lets the CLI warn about
	// a genuinely unusable token without crying wolf about a working one.
	Audience string `json:"audience,omitempty"`
}

// handleProtectedResourceMetadata serves the PRM document. Unauthenticated by
// design — a client cannot sign in until it knows where to sign in — and 404
// when interactive sign-in is not configured, so the CLI can say so plainly
// instead of guessing at an issuer.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Keycloak == nil || s.cfg.Login.Issuer == "" {
		writeError(w, http.StatusNotFound, CodeUnsupported, "interactive sign-in is not configured for this registry")
		return
	}
	login := s.cfg.Login

	// The resource identifier is the registry's own base URL, which is what
	// the audience check compares against by hostname. Not the token endpoint
	// and not the realm: RFC 9728 identifies the *resource*.
	resource := strings.TrimRight(s.cfg.PublicURL, "/")

	writeJSON(w, http.StatusOK, protectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   []string{strings.TrimRight(login.Issuer, "/")},
		ScopesSupported:        login.Scopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           s.service(),
		ClientID:               login.ClientID,
		Audience:               login.Audience,
	})
}

// prmURL is the absolute URL of this registry's PRM document, for the
// resource_metadata parameter of the WWW-Authenticate challenge.
func (s *Server) prmURL() string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + wellKnownPRM
}
