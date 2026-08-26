package login

import (
	"strings"
	"testing"
)

func TestDeviceSetupHint(t *testing.T) {
	d := &Discovery{
		Issuer:   "https://login.agentics.dk/realms/agentics",
		ClientID: "agent-registry-cli",
		Audience: "registry.agentics.dk",
		Registry: "registry.agentics.dk",
		Scopes:   []string{"openid", "offline_access"},
	}

	// The exact body the live realm returned on 2026-08-25.
	body := []byte(`{"error":"unauthorized_client","error_description":"Client is not allowed to initiate OAuth 2.0 Device Authorization Grant. The flow is disabled for the client."}`)
	got := deviceSetupHint(body, d)
	for _, want := range []string{"reconcile-cli-client.mjs", "agent-registry-cli", "https://login.agentics.dk"} {
		if !strings.Contains(got, want) {
			t.Errorf("unauthorized_client hint missing %q:\n%s", want, got)
		}
	}
	// KEYCLOAK_URL is the origin, not the realm URL — the script appends the realm.
	if strings.Contains(got, "KEYCLOAK_URL=https://login.agentics.dk/realms") {
		t.Errorf("hint passed a realm URL as KEYCLOAK_URL:\n%s", got)
	}

	// The script lives in another repository; a message that names it without
	// saying so sends a reader looking for a directory they do not have.
	for _, got := range []string{deviceSetupHint(body, d), AudienceSetupHint(d), redirectSetupHint(
		[]byte(`{"error":"invalid_request","error_description":"Invalid parameter: redirect_uri"}`), d, "http://127.0.0.1:51789/callback")} {
		if strings.Contains(got, "reconcile-") && !strings.Contains(got, "workspace") {
			t.Errorf("hint names a script without locating it:\n%s", got)
		}
	}

	// Anything else must fall through to the verbatim OAuth error, so a real
	// protocol failure is not mislabelled as a missing realm setting.
	for _, body := range []string{`{"error":"server_error"}`, `not json at all`, `{}`, `{"error":"invalid_scope"}`} {
		if got := deviceSetupHint([]byte(body), d); got != "" {
			t.Errorf("deviceSetupHint(%s) = %q, want empty", body, got)
		}
	}
}

func TestRedirectSetupHint(t *testing.T) {
	d := &Discovery{
		Issuer:   "https://login.agentics.dk/realms/agentics",
		ClientID: "agent-registry-cli",
		Audience: "registry.agentics.dk",
		Registry: "registry.agentics.dk",
	}
	// Keycloak's shape when the redirect URI is not registered on the client.
	body := []byte(`{"error":"invalid_grant","error_description":"Incorrect redirect_uri"}`)
	got := redirectSetupHint(body, d, "http://127.0.0.1:51789/callback")
	for _, want := range []string{"http://127.0.0.1:51789/callback", "reconcile-cli-client.mjs"} {
		if !strings.Contains(got, want) {
			t.Errorf("redirect hint missing %q:\n%s", want, got)
		}
	}
	// An unrelated failure must not be explained away as a missing redirect.
	if got := redirectSetupHint([]byte(`{"error":"invalid_grant","error_description":"Code not valid"}`), d, "x"); got != "" {
		t.Errorf("redirectSetupHint on an unrelated error = %q, want empty", got)
	}
}

// The device grant is the fallback, never the default, and the predicate that
// picks it must not fire on the environment this CLI most often runs in.
func TestLoopbackWaitIgnoresDisplay(t *testing.T) {
	t.Setenv("SSH_TTY", "")
	t.Setenv("VSCODE_IPC_HOOK_CLI", "")
	t.Setenv("TERM_PROGRAM", "")

	// A devcontainer has no DISPLAY and loopback works there anyway, because
	// the editor forwards the port. Unsetting DISPLAY must change nothing.
	t.Setenv("DISPLAY", "")
	if got := loopbackWait(); got != waitForCallback {
		t.Fatalf("an absent DISPLAY shortened the wait to %s — the loopback flow must get its full chance", got)
	}

	// A bare SSH login is the one case where the callback genuinely cannot
	// arrive, and there waiting the full five minutes helps nobody.
	t.Setenv("SSH_TTY", "/dev/pts/3")
	if got := loopbackWait(); got >= waitForCallback {
		t.Fatalf("bare ssh should shorten the wait, got %s", got)
	}

	// ...but an editor attached over Remote-SSH sets SSH_TTY too, and forwards
	// the port. The editor wins.
	t.Setenv("TERM_PROGRAM", "vscode")
	if got := loopbackWait(); got != waitForCallback {
		t.Fatalf("an attached editor forwards the port; want the full wait, got %s", got)
	}
}

func TestParseAudienceAndRegistryCheck(t *testing.T) {
	// JWT allows aud to be a bare string or an array; Keycloak emits both
	// shapes depending on how many audiences a token ends up with.
	for name, raw := range map[string]string{
		"array":  `["registry.agentics.dk","account"]`,
		"string": `"registry.agentics.dk"`,
	} {
		c := &Credential{Audience: "registry.agentics.dk", Audiences: parseAudience([]byte(raw))}
		if !c.HasRegistryAudience() {
			t.Errorf("%s: aud %s should satisfy the registry", name, raw)
		}
	}

	// The state this exists for: the scope was requested but silently dropped,
	// so the token is valid and useless.
	dropped := &Credential{Audience: "registry.agentics.dk", Audiences: parseAudience([]byte(`["account"]`))}
	if dropped.HasRegistryAudience() {
		t.Error("a token audienced only to account must not pass as registry-usable")
	}

	// No expected audience means the registry never said what to look for.
	if !(&Credential{}).HasRegistryAudience() {
		t.Error("an unset expected audience has nothing to warn about")
	}
	// Absent aud with an expectation is a miss, not a pass.
	if (&Credential{Audience: "registry.agentics.dk"}).HasRegistryAudience() {
		t.Error("a token with no aud at all must not pass")
	}
	if got := parseAudience(nil); got != nil {
		t.Errorf("parseAudience(nil) = %v, want nil", got)
	}
}
