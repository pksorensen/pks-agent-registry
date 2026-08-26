package dockercfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func withConfig(t *testing.T, initial string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	path := filepath.Join(dir, "config.json")
	if initial != "" {
		if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestRegisterHelperPreservesEverythingElse(t *testing.T) {
	// A real config.json: someone else's credsStore, another registry's auth,
	// and settings this tool knows nothing about.
	path := withConfig(t, `{
	  "credsStore": "dev-containers-cb4ddc41",
	  "auths": {"ghcr.io": {}, "registry.agentics.dk": {"auth": "b2xkOnBhc3N3b3Jk"}},
	  "currentContext": "desktop-linux",
	  "plugins": {"scan": {"skipped": "true"}}
	}`)

	changed, err := RegisterHelper("registry.agentics.dk")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first registration reported no change")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["credsStore"] != "dev-containers-cb4ddc41" {
		t.Fatalf("credsStore was disturbed: %v", cfg["credsStore"])
	}
	if cfg["currentContext"] != "desktop-linux" || cfg["plugins"] == nil {
		t.Fatalf("unrelated settings were dropped: %s", raw)
	}
	helpers := cfg["credHelpers"].(map[string]any)
	if helpers["registry.agentics.dk"] != HelperName {
		t.Fatalf("credHelpers not set: %v", helpers)
	}
	auths := cfg["auths"].(map[string]any)
	if _, stale := auths["registry.agentics.dk"]; stale {
		t.Fatal("the superseded password entry was left behind")
	}
	if _, ok := auths["ghcr.io"]; !ok {
		t.Fatal("another registry's auth entry was removed")
	}

	// Idempotent.
	changed, err = RegisterHelper("registry.agentics.dk")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("re-registration reported a change")
	}
}

func TestUnregisterHelperLeavesOtherHelpersAlone(t *testing.T) {
	withConfig(t, `{"credHelpers": {"registry.agentics.dk": "agentics", "myreg.example": "ecr-login"}}`)

	changed, err := UnregisterHelper("myreg.example")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("removed a helper this tool does not own")
	}

	if changed, err := UnregisterHelper("registry.agentics.dk"); err != nil || !changed {
		t.Fatalf("unregister: changed=%v err=%v", changed, err)
	}
	name, err := HelperFor("myreg.example")
	if err != nil {
		t.Fatal(err)
	}
	if name != "ecr-login" {
		t.Fatalf("other helper lost: %q", name)
	}
}

func TestReadMissingConfigIsEmptyNotAnError(t *testing.T) {
	withConfig(t, "")
	cfg, err := Read()
	if err != nil {
		t.Fatalf("Read on a machine that never ran docker login: %v", err)
	}
	if len(cfg) != 0 {
		t.Fatalf("want empty config, got %v", cfg)
	}
}
