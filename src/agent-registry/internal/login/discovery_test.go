package login

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// prmServer stands in for a registry: a /v2/ that challenges with a pointer to
// its metadata, and the metadata document itself.
func prmServer(t *testing.T, advertiseChallenge bool, doc map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, _ *http.Request) {
		if advertiseChallenge {
			w.Header().Add("WWW-Authenticate",
				`Bearer realm="`+srv.URL+`/token",service="reg.example.com",resource_metadata="`+srv.URL+prmPath+`"`)
		}
		w.Header().Add("WWW-Authenticate", `Basic realm="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc(prmPath, func(w http.ResponseWriter, _ *http.Request) {
		if doc == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchDiscoveryFollowsTheChallenge(t *testing.T) {
	srv := prmServer(t, true, map[string]any{
		"resource":              "https://reg.example.com",
		"authorization_servers": []string{"https://issuer.example.com/realms/r"},
		"scopes_supported":      []string{"openid", "offline_access"},
		"client_id":             "someone-elses-cli",
	})

	d, err := FetchDiscovery(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchDiscovery: %v", err)
	}
	if d.Issuer != "https://issuer.example.com/realms/r" {
		t.Fatalf("issuer = %q", d.Issuer)
	}
	// The point of the whole exercise: a third party's document names their
	// client and their scopes, and the CLI uses them without a rebuild.
	if d.ClientID != "someone-elses-cli" {
		t.Fatalf("a resource that names its own client must win over our default, got %q", d.ClientID)
	}
	if len(d.Scopes) != 2 || d.Scopes[0] != "openid" {
		t.Fatalf("scopes must come from the document, got %v", d.Scopes)
	}
	// The audience is derived from the resource identifier, not from the
	// hostname the user happened to type.
	if d.Audience != "reg.example.com" {
		t.Fatalf("audience = %q, want the resource host", d.Audience)
	}
}

// A resource that challenges without a pointer is still discoverable at the
// well-known path — the fallback RFC 9728 defines.
func TestFetchDiscoveryFallsBackToWellKnownPath(t *testing.T) {
	srv := prmServer(t, false, map[string]any{
		"resource":              "https://reg.example.com",
		"authorization_servers": []string{"https://issuer.example.com/realms/r"},
	})
	d, err := FetchDiscovery(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchDiscovery: %v", err)
	}
	if d.Issuer != "https://issuer.example.com/realms/r" {
		t.Fatalf("issuer = %q", d.Issuer)
	}
	// No client_id in the document, so ours applies.
	if d.ClientID != DefaultClientID {
		t.Fatalf("client_id = %q, want the built-in default", d.ClientID)
	}
}

func TestFetchDiscoveryNotConfigured(t *testing.T) {
	srv := prmServer(t, false, nil)
	if _, err := FetchDiscovery(srv.Client(), srv.URL); err != ErrNotConfigured {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

// FetchEndpoints deliberately tolerates an issuer with no device grant, so the
// flow that needs it has to be the one that complains — otherwise the failure
// arrives as an empty-URL POST.
func TestStartDeviceExplainsAMissingEndpoint(t *testing.T) {
	d := &Discovery{Issuer: "https://issuer.example.com/realms/r", ClientID: "agent-registry-cli"}
	_, err := StartDevice(nil, &Endpoints{Token: "https://issuer.example.com/token"}, d)
	if err == nil {
		t.Fatal("StartDevice with no device endpoint must fail")
	}
	for _, want := range []string{"device authorization endpoint", "agent-registry-cli"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "unsupported protocol scheme") {
		t.Errorf("StartDevice POSTed to an empty URL: %v", err)
	}
}
