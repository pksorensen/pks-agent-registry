package login

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// authServer is a minimal authorization server: it records the authorize
// request and answers the token exchange.
type authServer struct {
	*httptest.Server
	authorize url.Values
	tokenForm url.Values
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	a := &authServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(_ http.ResponseWriter, r *http.Request) {
		a.authorize = r.URL.Query()
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		a.tokenForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "refresh_token": "rt", "expires_in": 300,
		})
	})
	a.Server = httptest.NewServer(mux)
	t.Cleanup(a.Close)
	return a
}

func (a *authServer) endpoints() *Endpoints {
	return &Endpoints{Authorization: a.URL + "/auth", Token: a.URL + "/token"}
}

// TestLoopbackRoundTrip drives the whole flow with a fake browser: wait for the
// authorize URL, then call the redirect the way a browser would.
func TestLoopbackRoundTrip(t *testing.T) {
	as := newAuthServer(t)
	d := &Discovery{
		Issuer:   as.URL,
		ClientID: "agent-registry-cli",
		Audience: "reg.example.com",
		Scopes:   []string{"openid", "offline_access"},
		Registry: "reg.example.com",
	}

	done := make(chan struct{})
	onURL := func(raw string) {
		go func() {
			defer close(done)
			u, err := url.Parse(raw)
			if err != nil {
				t.Error(err)
				return
			}
			q := u.Query()
			// PKCE is not optional, and plain is not acceptable.
			if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
				t.Errorf("authorize request is not using PKCE S256: %v", q)
			}
			// RFC 8707: sent even where it is ignored, so an authorization
			// server that honours it gets the right audience for free.
			if q.Get("resource") == "" {
				t.Errorf("authorize request carries no resource indicator: %v", q)
			}
			// A browser visits the authorization endpoint first; the callback
			// only happens because of what it found there.
			if resp, err := http.Get(raw); err == nil {
				resp.Body.Close()
			}

			cb := q.Get("redirect_uri")
			if !strings.HasPrefix(cb, "http://127.0.0.1:") {
				t.Errorf("redirect_uri = %q, want a 127.0.0.1 loopback", cb)
			}
			resp, err := http.Get(cb + "?code=the-code&state=" + url.QueryEscape(q.Get("state")))
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			// The browser must be answered, always: a hanging tab is how a
			// successful sign-in looks like a failed one.
			if resp.StatusCode != http.StatusOK {
				t.Errorf("callback page returned %d", resp.StatusCode)
			}
		}()
	}

	cred, err := Loopback(context.Background(), as.Client(), as.endpoints(), d, onURL)
	if err != nil {
		t.Fatalf("Loopback: %v", err)
	}
	<-done

	if cred.AccessToken != "at" || cred.RefreshToken != "rt" {
		t.Fatalf("credential mismatch: %+v", cred)
	}
	// The code_verifier has to be the one whose hash was sent up front, and the
	// redirect_uri has to be spelled identically in both requests.
	if as.tokenForm.Get("code_verifier") == "" {
		t.Error("token exchange sent no code_verifier")
	}
	if as.tokenForm.Get("redirect_uri") != as.authorize.Get("redirect_uri") {
		t.Errorf("redirect_uri differs between authorize (%q) and token (%q)",
			as.authorize.Get("redirect_uri"), as.tokenForm.Get("redirect_uri"))
	}
}

// A callback from somewhere other than the request we started must be refused
// even though it carries a usable-looking code.
func TestLoopbackRejectsStateMismatch(t *testing.T) {
	as := newAuthServer(t)
	d := &Discovery{Issuer: as.URL, ClientID: "c", Registry: "reg.example.com"}

	onURL := func(raw string) {
		go func() {
			u, _ := url.Parse(raw)
			resp, err := http.Get(u.Query().Get("redirect_uri") + "?code=the-code&state=not-ours")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	_, err := Loopback(context.Background(), as.Client(), as.endpoints(), d, onURL)
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("err = %v, want a state mismatch", err)
	}
}

func TestLoopbackHonoursContextCancel(t *testing.T) {
	as := newAuthServer(t)
	d := &Discovery{Issuer: as.URL, ClientID: "c", Registry: "reg.example.com"}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, err := Loopback(ctx, as.Client(), as.endpoints(), d, nil); err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
