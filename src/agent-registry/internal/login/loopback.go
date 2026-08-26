package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// redirectPath is the callback path the authorization server sends the browser
// back to. Part of the registered redirect URI, so it cannot vary per run.
const redirectPath = "/callback"

// loopbackPorts are tried in order before falling back to an ephemeral one.
//
// A fixed list first, because an authorization server administered properly
// registers exact redirect URIs — RFC 8252 §7.3 says a server SHOULD accept any
// port on a loopback redirect, and Keycloak does not implement that, so a third
// party pointing this CLI at their own issuer has three URIs to register rather
// than a wildcard to talk themselves into. Same three ports pks-cli uses, so
// one registration covers both.
var loopbackPorts = []int{51789, 51790, 51791}

// waitForCallback is long enough for a login that needs a password manager and
// an MFA prompt, short enough that a forgotten terminal frees the port the same
// morning.
const waitForCallback = 5 * time.Minute

// ErrLoopbackUnavailable means no loopback port could be bound at all. The
// caller falls back to the device grant rather than failing the sign-in.
var ErrLoopbackUnavailable = errors.New("no loopback port could be bound")

// ErrCallbackTimeout means the browser never came back. Distinguished from
// other failures because the fix is a different flow, not a retry.
var ErrCallbackTimeout = errors.New("timed out waiting for the browser to come back")

// callbackResult is what the HTTP handler hands back to the waiting flow.
type callbackResult struct {
	code  string
	state string
	err   string
}

// Loopback performs the RFC 8252 authorization-code flow with PKCE against a
// loopback redirect. onURL is called with the authorization URL before the
// browser is opened, so the URL is on screen even when no browser starts —
// which is the whole reason this works over a forwarded port in an editor's
// remote session.
func Loopback(ctx context.Context, client *http.Client, ep *Endpoints, d *Discovery, onURL func(string)) (*Credential, error) {
	if ep.Authorization == "" {
		return nil, fmt.Errorf("%s publishes no authorization endpoint", d.Issuer)
	}

	ln, port, err := listenLoopback()
	if err != nil {
		return nil, ErrLoopbackUnavailable
	}
	defer ln.Close()

	// Spelled without a trailing slash, exactly as it must be registered at the
	// authorization server: the redirect_uri is compared as a string, and the
	// token exchange has to repeat the same spelling.
	redirect := fmt.Sprintf("http://127.0.0.1:%d%s", port, redirectPath)

	verifier, err := randomBase64URL(32)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := randomBase64URL(16)
	if err != nil {
		return nil, err
	}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {d.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(d.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	// RFC 8707. Keycloak ignores it — the audience arrives via a mapper on the
	// client instead — but an authorization server that does implement resource
	// indicators is then handled correctly with no special case.
	if d.Audience != "" {
		q.Set("resource", BaseURL(d.Audience))
	}
	authorizeURL := ep.Authorization + "?" + q.Encode()

	// Deliberately no browser launch here. Opening a browser is a side effect
	// on somebody's desktop, and this function is also driven by tests and by
	// callers that only want the URL — so the caller is handed the URL and
	// decides. SignIn is the one that opens it.
	if onURL != nil {
		onURL(authorizeURL)
	}

	results := make(chan callbackResult, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != redirectPath {
			http.NotFound(w, r)
			return
		}
		v := r.URL.Query()
		res := callbackResult{code: v.Get("code"), state: v.Get("state"), err: v.Get("error")}

		// Answer the browser before anything else can go wrong: a tab that
		// hangs on a dead socket is how a successful login looks like a failed
		// one. Nothing below this point can stop the page from rendering.
		writeCallbackPage(w, res.err == "" && res.code != "" && res.state == state, res.err)

		select {
		case results <- res:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	var res callbackResult
	select {
	case res = <-results:
	case <-time.After(waitForCallback):
		return nil, ErrCallbackTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if res.err != "" {
		if res.err == "access_denied" {
			return nil, ErrDenied
		}
		return nil, fmt.Errorf("sign-in failed: %s", res.err)
	}
	if res.code == "" {
		return nil, errors.New("the authorization server returned no authorization code")
	}
	// A mismatched state is the one case worth naming precisely: it means the
	// callback did not come from the request we started.
	if res.state != state {
		return nil, errors.New("state mismatch — the callback was not ours")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.code},
		"redirect_uri":  {redirect},
		"client_id":     {d.ClientID},
		"code_verifier": {verifier},
	}
	if d.Audience != "" {
		form.Set("resource", BaseURL(d.Audience))
	}
	resp, err := postForm(client, ep.Token, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		if hint := redirectSetupHint(body, d, redirect); hint != "" {
			return nil, errors.New(hint)
		}
		return nil, fmt.Errorf("sign-in failed: %s: %s", resp.Status, oauthMessage(body))
	}
	return credentialFromTokenResponse(d, body)
}

// listenLoopback binds 127.0.0.1 on the first free fixed port, falling back to
// an ephemeral one. The IP literal, not "localhost": RFC 8252 §7.3 prefers it,
// because "localhost" resolves through a name lookup that other software on
// the machine may be able to influence.
func listenLoopback() (net.Listener, int, error) {
	for _, p := range loopbackPorts {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			return ln, p, nil
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
}

func writeCallbackPage(w http.ResponseWriter, ok bool, errCode string) {
	message := "You&#39;re signed in. Close this tab and go back to the terminal."
	if !ok {
		message = "Sign-in failed. Go back to the terminal."
		if errCode != "" {
			message = "Sign-in failed: " + htmlEscape(errCode) + ". Go back to the terminal."
		}
	}
	html := "<!doctype html><meta charset=utf-8><title>agent-registry</title>" +
		`<body style="font-family:system-ui;background:#0b0b0c;color:#ededef;text-align:center;padding-top:15vh">` +
		`<h2 style="color:#f87f2e">agent-registry</h2><p>` + message + "</p>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, html)
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// tryOpenBrowser is a convenience, never a requirement: the URL is printed
// first, and on a forwarded port a human clicking it in the terminal is the
// normal path rather than the fallback.
func tryOpenBrowser(target string) {
	// A test that reaches this has a bug, and the symptom lands on a human's
	// desktop as a browser tab pointing at a fake authorization server — so it
	// is stopped here rather than left to be noticed.
	if testing.Testing() {
		return
	}
	var cmd *exec.Cmd
	switch {
	case runtime.GOOS == "windows":
		cmd = exec.Command("cmd", "/c", "start", "", target)
	case os.Getenv("BROWSER") != "":
		cmd = exec.Command(os.Getenv("BROWSER"), target)
	case runtime.GOOS == "darwin":
		cmd = exec.Command("open", target)
	default:
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return // headless — the printed URL is the fallback
		}
		cmd = exec.Command("xdg-open", target)
	}
	_ = cmd.Start()
}
