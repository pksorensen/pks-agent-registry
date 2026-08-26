package login

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AGENT_REGISTRY_CONFIG", dir)
	return filepath.Join(dir, "credentials.json")
}

func TestRoundTripAndForget(t *testing.T) {
	path := withStore(t)
	if err := Put(&Credential{
		Registry:     "https://registry.agentics.dk/",
		Issuer:       "https://login.agentics.dk/realms/agentics",
		ClientID:     "agentics-cli",
		AccessToken:  "at",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(time.Hour),
		Username:     "poul",
	}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credential file mode %o — a refresh token must not be readable by anyone else", perm)
	}

	// The URL spelling and the bare hostname are the same registry.
	c, err := Get("registry.agentics.dk")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "poul" || !c.Fresh(time.Now()) {
		t.Fatalf("credential mismatch: %+v", c)
	}

	if err := PutStatic(&Static{Registry: "registry.agentics.dk", Username: "owner", Secret: "pw"}); err != nil {
		t.Fatal(err)
	}
	removed, err := Forget("registry.agentics.dk")
	if err != nil || !removed {
		t.Fatalf("Forget: removed=%v err=%v", removed, err)
	}
	if _, found, err := GetStatic("registry.agentics.dk"); err != nil || found {
		t.Fatal("Forget left the stored password behind")
	}
	if _, err := Get("registry.agentics.dk"); err != ErrNotSignedIn {
		t.Fatalf("want ErrNotSignedIn, got %v", err)
	}
}

func TestFreshLeavesSlackBeforeExpiry(t *testing.T) {
	now := time.Now()
	c := &Credential{AccessToken: "at", ExpiresAt: now.Add(30 * time.Second)}
	if c.Fresh(now) {
		t.Fatal("a token 30s from expiry must be refreshed, not handed to docker")
	}
	c.ExpiresAt = now.Add(10 * time.Minute)
	if !c.Fresh(now) {
		t.Fatal("a token good for ten more minutes should be reused")
	}
	if (&Credential{ExpiresAt: now.Add(time.Hour)}).Fresh(now) {
		t.Fatal("an empty token is never fresh")
	}
}

func TestNormalizeRegistry(t *testing.T) {
	for in, want := range map[string]string{
		"":                              DefaultRegistry,
		"registry.agentics.dk":          "registry.agentics.dk",
		"https://registry.agentics.dk/": "registry.agentics.dk",
		"localhost:5000":                "localhost:5000",
	} {
		if got := NormalizeRegistry(in); got != want {
			t.Fatalf("NormalizeRegistry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBaseURLOnlyDowngradesLoopback(t *testing.T) {
	for in, want := range map[string]string{
		"registry.agentics.dk": "https://registry.agentics.dk",
		"localhost:5000":       "http://localhost:5000",
		"127.0.0.1:5000":       "http://127.0.0.1:5000",
		"notlocalhost.dk":      "https://notlocalhost.dk",
	} {
		if got := BaseURL(in); got != want {
			t.Fatalf("BaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}
