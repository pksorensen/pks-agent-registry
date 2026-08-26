package login

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

// Credential is one signed-in registry. The refresh token is the durable part;
// the access token is a cache so the credential helper does not hit Keycloak
// on every single docker operation.
type Credential struct {
	Registry     string    `json:"registry"`
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"clientId"`
	Audience     string    `json:"audience,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	AccessToken  string    `json:"accessToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Username     string    `json:"username,omitempty"`
	// Audiences is the token's `aud` claim, kept so the CLI can tell a person
	// their sign-in worked but will be refused at pull time. Keycloak ignores
	// the RFC 8707 `resource` parameter silently, so a realm whose CLI client
	// has no audience mapper hands back a perfectly valid, perfectly useless
	// token and says nothing about it.
	Audiences  []string  `json:"audiences,omitempty"`
	SignedInAt time.Time `json:"signedInAt,omitempty"`
}

// Fresh reports whether the cached access token is still usable. The minute of
// slack means a token is never handed to docker seconds before it dies.
func (c *Credential) Fresh(now time.Time) bool {
	return c.AccessToken != "" && !c.ExpiresAt.IsZero() && now.Add(time.Minute).Before(c.ExpiresAt)
}

// Static is a plain username/password for one registry — what `docker login`
// hands the credential helper to store. Kept beside the OIDC credentials so
// that registering the helper does not break `docker login` for an owner
// account, which is still the only way in on a registry without Keycloak.
type Static struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

// file is the on-disk shape: two maps keyed by registry hostname.
type file struct {
	Credentials map[string]*Credential `json:"credentials"`
	Static      map[string]*Static     `json:"static,omitempty"`
}

// Path is the credential file's location. XDG_CONFIG_HOME is honoured; the
// fallback is ~/.config/agent-registry/credentials.json on every platform,
// including Windows, so the path is the same one the docs can name.
func Path() (string, error) {
	if dir := os.Getenv("AGENT_REGISTRY_CONFIG"); dir != "" {
		return filepath.Join(dir, "credentials.json"), nil
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "agent-registry", "credentials.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "agent-registry", "credentials.json"), nil
}

func load() (*file, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &file{Credentials: map[string]*Credential{}, Static: map[string]*Static{}}, nil
	}
	if err != nil {
		return nil, err
	}
	f := &file{}
	if err := json.Unmarshal(raw, f); err != nil {
		return nil, err
	}
	if f.Credentials == nil {
		f.Credentials = map[string]*Credential{}
	}
	if f.Static == nil {
		f.Static = map[string]*Static{}
	}
	return f, nil
}

func save(f *file) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	// Write-then-rename so a crash mid-write cannot leave a half-parsed file
	// that locks the user out of every registry at once. The temp file is
	// created 0600 from the start — never world-readable, not even briefly.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// Windows rename fails onto an existing file.
		_ = os.Remove(path)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Get returns the stored credential for a registry.
func Get(registry string) (*Credential, error) {
	f, err := load()
	if err != nil {
		return nil, err
	}
	c, ok := f.Credentials[NormalizeRegistry(registry)]
	if !ok {
		return nil, ErrNotSignedIn
	}
	return c, nil
}

// ErrNotSignedIn means no credential is stored for that registry.
var ErrNotSignedIn = errors.New("not signed in")

// Put stores or replaces a registry's credential.
func Put(c *Credential) error {
	f, err := load()
	if err != nil {
		return err
	}
	c.Registry = NormalizeRegistry(c.Registry)
	f.Credentials[c.Registry] = c
	return save(f)
}

// List returns every stored credential, sorted by registry.
func List() ([]*Credential, error) {
	f, err := load()
	if err != nil {
		return nil, err
	}
	out := make([]*Credential, 0, len(f.Credentials))
	for _, c := range f.Credentials {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Registry < out[j].Registry })
	return out, nil
}

// GetStatic returns a stored username/password for a registry.
func GetStatic(registry string) (*Static, bool, error) {
	f, err := load()
	if err != nil {
		return nil, false, err
	}
	st, ok := f.Static[NormalizeRegistry(registry)]
	return st, ok, nil
}

// PutStatic stores a username/password for a registry.
func PutStatic(st *Static) error {
	f, err := load()
	if err != nil {
		return err
	}
	st.Registry = NormalizeRegistry(st.Registry)
	f.Static[st.Registry] = st
	return save(f)
}

// Forget removes every credential this tool holds for a registry — the OIDC
// session and any stored username/password. Reports whether anything went.
func Forget(registry string) (bool, error) {
	f, err := load()
	if err != nil {
		return false, err
	}
	key := NormalizeRegistry(registry)
	_, hadOIDC := f.Credentials[key]
	_, hadStatic := f.Static[key]
	if !hadOIDC && !hadStatic {
		return false, nil
	}
	delete(f.Credentials, key)
	delete(f.Static, key)
	return true, save(f)
}

// Registries lists every registry this tool holds any credential for.
func Registries() ([]string, error) {
	f, err := load()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for k := range f.Credentials {
		seen[k] = true
	}
	for k := range f.Static {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// HasRegistryAudience reports whether the token carries the audience the
// registry requires. An empty expected audience means the registry never told
// us what to look for, so there is nothing to warn about.
func (c *Credential) HasRegistryAudience() bool {
	if c == nil || c.Audience == "" {
		return true
	}
	for _, a := range c.Audiences {
		if a == c.Audience {
			return true
		}
	}
	return false
}
