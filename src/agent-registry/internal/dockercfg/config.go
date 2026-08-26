// Package dockercfg reads and edits ~/.docker/config.json — specifically the
// credHelpers map, which is how docker is told to ask an external program for
// one registry's credentials.
//
// credHelpers is per-registry and takes precedence over the global credsStore
// for that host. That matters here: VS Code's dev-containers helper owns
// credsStore and rewrites it on reconnect, so registering ours per-registry
// keeps the two from fighting.
package dockercfg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// HelperName is the suffix docker appends to "docker-credential-" when it
// looks the helper up on PATH.
const HelperName = "agentics"

// BinaryName is the file docker actually executes.
const BinaryName = "docker-credential-" + HelperName

// Path returns docker's config.json location, honouring DOCKER_CONFIG.
func Path() (string, error) {
	if dir := os.Getenv("DOCKER_CONFIG"); dir != "" {
		return filepath.Join(dir, "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".docker", "config.json"), nil
}

// Read returns config.json as a generic map. A missing file is an empty
// config, not an error — plenty of machines have never run `docker login`.
func Read() (map[string]any, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	cfg := map[string]any{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Write persists config.json, preserving every key it did not touch. Docker
// stores auths and other people's settings in this file; a whole-file rewrite
// from a partial model would silently drop them.
func Write(cfg map[string]any) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(path)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// HelperFor returns the credential helper registered for a registry, if any.
func HelperFor(registry string) (string, error) {
	cfg, err := Read()
	if err != nil {
		return "", err
	}
	helpers, _ := cfg["credHelpers"].(map[string]any)
	name, _ := helpers[registry].(string)
	return name, nil
}

// RegisterHelper points docker at our helper for one registry. Reports
// whether anything changed.
func RegisterHelper(registry string) (bool, error) {
	cfg, err := Read()
	if err != nil {
		return false, err
	}
	helpers, _ := cfg["credHelpers"].(map[string]any)
	if helpers == nil {
		helpers = map[string]any{}
	}
	if existing, _ := helpers[registry].(string); existing == HelperName {
		return false, nil
	}
	helpers[registry] = HelperName
	cfg["credHelpers"] = helpers

	// A stale `auths` entry for the same host shadows nothing — docker checks
	// credHelpers first — but leaving a password from an old `docker login`
	// lying around after the user moved to a token is not tidy. Drop it.
	if auths, ok := cfg["auths"].(map[string]any); ok {
		delete(auths, registry)
	}
	return true, Write(cfg)
}

// UnregisterHelper removes our registration for one registry. Reports whether
// anything changed. Another helper's registration is left alone.
func UnregisterHelper(registry string) (bool, error) {
	cfg, err := Read()
	if err != nil {
		return false, err
	}
	helpers, _ := cfg["credHelpers"].(map[string]any)
	if existing, _ := helpers[registry].(string); existing != HelperName {
		return false, nil
	}
	delete(helpers, registry)
	if len(helpers) == 0 {
		delete(cfg, "credHelpers")
	} else {
		cfg["credHelpers"] = helpers
	}
	return true, Write(cfg)
}
