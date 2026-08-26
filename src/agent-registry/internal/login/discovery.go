// Package login implements interactive sign-in for the agent-registry CLI:
// discovery of the registry's authorization server, the OAuth 2.0
// authorization-code flow with a loopback redirect, the device grant as a
// fallback, a credential file the Docker credential helper reads back, and the
// silent refresh in between (ADR 0004).
//
// Loopback first, device second. The loopback flow is the one that finishes
// without the user transcribing anything, and it works in a devcontainer or
// over an editor's remote session because the editor forwards the port — the
// same reason `gh auth login` and `az login` work there. The device grant is
// kept for the case the port genuinely cannot be reached: a raw SSH session or
// a tmux pane with no forwarding, which is where this CLI also runs.
//
// Nothing here is Keycloak-specific. The registry names its authorization
// server in an RFC 9728 metadata document, so pointing this binary at someone
// else's registry sends it to someone else's issuer with no rebuild.
package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultRegistry is the registry `agent-registry login` signs into when the
// user names none.
const DefaultRegistry = "registry.agentics.dk"

// prmPath is the RFC 9728 Protected Resource Metadata path, used when the
// registry's challenge does not name one.
const prmPath = "/.well-known/oauth-protected-resource"

// Discovery is what the CLI needs in order to sign in, assembled from the
// registry's RFC 9728 document.
type Discovery struct {
	Issuer   string
	ClientID string
	Audience string
	Scopes   []string
	Registry string
}

// protectedResourceMetadata is the RFC 9728 document. client_id is our
// extension — the RFC has no field for a public client id and dynamic client
// registration is not something real-world authorization servers have adopted,
// so a resource that wants to be signed into names its client here.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
	ClientID             string   `json:"client_id"`
	Audience             string   `json:"audience"`
}

// ErrNotConfigured means the registry answered, but interactive sign-in is
// not armed on it.
var ErrNotConfigured = errors.New("this registry does not offer interactive sign-in")

// DefaultClientID is used only when a registry advertises no client_id of its
// own. A third party's document naming theirs always wins over this.
const DefaultClientID = "agent-registry-cli"

// FetchDiscovery asks a registry how to sign into it, following RFC 9728: hit
// the API, read resource_metadata out of the WWW-Authenticate challenge, fetch
// that document. registry is a bare hostname ("registry.agentics.dk"); http://
// is only used for a localhost host, so a development registry needs no TLS.
func FetchDiscovery(client *http.Client, registry string) (*Discovery, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	base := BaseURL(registry)

	// The challenge is the authoritative pointer; the well-known path is the
	// fallback for a resource that does not advertise one. Trying the
	// challenge first is what makes this work from a bare `docker pull`
	// failure, where the URL is all anyone has.
	metaURL := challengeResourceMetadata(client, base+"/v2/")
	if metaURL == "" {
		metaURL = base + prmPath
	}

	meta, err := fetchPRM(client, metaURL)
	if err != nil {
		return nil, err
	}
	if len(meta.AuthorizationServers) == 0 {
		return nil, ErrNotConfigured
	}

	d := &Discovery{
		Issuer:   strings.TrimRight(meta.AuthorizationServers[0], "/"),
		ClientID: meta.ClientID,
		Scopes:   meta.ScopesSupported,
		// The resource's own word on what it requires beats guessing from its
		// URL: the two differ whenever a registry is reached at some other
		// hostname than the one its realm stamps into `aud`.
		Audience: firstNonEmpty(meta.Audience, resourceHost(meta.Resource)),
		Registry: NormalizeRegistry(registry),
	}
	if d.ClientID == "" {
		d.ClientID = DefaultClientID
	}
	if len(d.Scopes) == 0 {
		d.Scopes = []string{"openid", "offline_access"}
	}
	if d.Audience == "" {
		d.Audience = d.Registry
	}
	if d.Issuer == "" {
		return nil, ErrNotConfigured
	}
	return d, nil
}

func fetchPRM(client *http.Client, metaURL string) (*protectedResourceMetadata, error) {
	resp, err := client.Get(metaURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotConfigured
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", metaURL, resp.Status)
	}
	meta := &protectedResourceMetadata{}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(meta); err != nil {
		return nil, err
	}
	return meta, nil
}

// resourceMetadataRE pulls the resource_metadata parameter out of a
// WWW-Authenticate challenge. A hand-rolled match rather than a full
// challenge parser: this is the only parameter we need, and the header's
// comma-and-quote grammar is more trouble than it is worth for one field.
var resourceMetadataRE = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// challengeResourceMetadata performs an unauthenticated probe and returns the
// resource_metadata URL the resource advertises, or "" if it advertises none.
// Every failure returns "" — this is a hint, and the caller has a fallback.
func challengeResourceMetadata(client *http.Client, probeURL string) string {
	resp, err := client.Get(probeURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	for _, h := range resp.Header.Values("WWW-Authenticate") {
		if m := resourceMetadataRE.FindStringSubmatch(h); m != nil {
			return m[1]
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// resourceHost reduces an RFC 9728 resource identifier to the hostname the
// token's audience is spelled with. Returns "" when it will not parse, and the
// caller falls back to the registry name.
func resourceHost(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return ""
	}
	if u, err := url.Parse(resource); err == nil && u.Host != "" {
		return u.Host
	}
	return ""
}

// BaseURL turns a registry hostname into a base URL. Plain http only for
// loopback hosts — everything else is https, with no way to downgrade it.
func BaseURL(registry string) string {
	registry = strings.TrimRight(strings.TrimSpace(registry), "/")
	if strings.Contains(registry, "://") {
		return registry
	}
	host := registry
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return "http://" + registry
	}
	return "https://" + registry
}

// NormalizeRegistry strips a scheme and trailing slash so the same registry is
// keyed identically however the user spelled it. Empty means DefaultRegistry.
func NormalizeRegistry(registry string) string {
	registry = strings.TrimSpace(registry)
	if registry == "" {
		return DefaultRegistry
	}
	if u, err := url.Parse(registry); err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimRight(registry, "/")
}
