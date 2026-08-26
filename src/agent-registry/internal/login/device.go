package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/oidc"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

// Endpoints are the issuer endpoints the two sign-in flows use. Device is
// empty on an issuer that offers no device grant, which is not an error until
// something actually asks for that flow.
type Endpoints struct {
	Authorization string
	Device        string
	Token         string
}

// FetchEndpoints reads the issuer's OpenID configuration. Only the token
// endpoint is required here: the authorization and device endpoints are each
// checked by the flow that needs them, so an issuer missing one can still be
// signed into through the other.
func FetchEndpoints(client *http.Client, issuer string) (*Endpoints, error) {
	doc, err := oidc.Discover(client, strings.TrimRight(issuer, "/"))
	if err != nil {
		return nil, err
	}
	if doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("%s does not advertise a token endpoint", issuer)
	}
	return &Endpoints{
		Authorization: doc.AuthorizationEndpoint,
		Device:        doc.DeviceAuthorizationEndpoint,
		Token:         doc.TokenEndpoint,
	}, nil
}

// DeviceAuth is the issuer's response to the device authorization request.
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	// verifier is the PKCE secret StartDevice generated, kept so PollDevice can
	// present it on the token request. Not part of the issuer's response.
	verifier string
}

// BestURL is the URL to show the user: the one with the code already in it
// when the issuer offers it, so nothing has to be typed.
func (d *DeviceAuth) BestURL() string {
	if d.VerificationURIComplete != "" {
		return d.VerificationURIComplete
	}
	return d.VerificationURI
}

// StartDevice begins the device authorization grant.
func StartDevice(client *http.Client, ep *Endpoints, d *Discovery) (*DeviceAuth, error) {
	// FetchEndpoints does not insist on this one, because an issuer without a
	// device grant can still be signed into through the browser. It is this
	// flow's job to say so, rather than POSTing to an empty URL and reporting
	// an unsupported protocol scheme.
	if ep.Device == "" {
		return nil, fmt.Errorf("%s advertises no device authorization endpoint — sign in through the browser instead, or enable the OAuth 2.0 device grant on client %q", d.Issuer, d.ClientID)
	}
	// PKCE on the device grant. RFC 8628 does not require it, but a client
	// configured to enforce S256 — which ours is, and which is the right
	// setting for a public client — has Keycloak refuse the device request
	// outright with "Missing parameter: code_challenge_method". Measured
	// against the live realm on 2026-08-25, immediately after the client was
	// created. It costs nothing on an issuer that does not ask for it.
	verifier, err := randomBase64URL(32)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	form := url.Values{
		"client_id":             {d.ClientID},
		"scope":                 {strings.Join(d.Scopes, " ")},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	resp, err := postForm(client, ep.Device, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		if hint := deviceSetupHint(body, d); hint != "" {
			return nil, errors.New(hint)
		}
		return nil, fmt.Errorf("device authorization failed: %s: %s", resp.Status, oauthMessage(body))
	}
	auth := &DeviceAuth{}
	if err := json.Unmarshal(body, auth); err != nil {
		return nil, err
	}
	if auth.DeviceCode == "" {
		return nil, errors.New("device authorization returned no device_code")
	}
	auth.verifier = verifier
	if auth.Interval <= 0 {
		auth.Interval = 5
	}
	return auth, nil
}

// ErrDenied means the user rejected the sign-in in the browser.
var ErrDenied = errors.New("sign-in was denied")

// PollDevice waits for the user to finish in the browser and returns the
// resulting credential. It honours the issuer's polling interval and the
// slow_down back-off, so it never hammers Keycloak.
func PollDevice(ctx context.Context, client *http.Client, ep *Endpoints, d *Discovery, auth *DeviceAuth) (*Credential, error) {
	interval := time.Duration(auth.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(max(auth.ExpiresIn, 60)) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return nil, errors.New("the sign-in code expired before it was approved")
		}

		form := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {auth.DeviceCode},
			"client_id":   {d.ClientID},
		}
		if auth.verifier != "" {
			form.Set("code_verifier", auth.verifier)
		}
		resp, err := postForm(client, ep.Token, form)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return credentialFromTokenResponse(d, body)
		}
		switch oauthError(body) {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return nil, ErrDenied
		case "expired_token":
			return nil, errors.New("the sign-in code expired before it was approved")
		default:
			return nil, fmt.Errorf("sign-in failed: %s: %s", resp.Status, oauthMessage(body))
		}
	}
}

// Refresh exchanges the stored refresh token for a new access token. The
// returned credential carries whatever refresh token the issuer rotated in.
func Refresh(client *http.Client, c *Credential) (*Credential, error) {
	if c.RefreshToken == "" {
		return nil, ErrNotSignedIn
	}
	ep, err := FetchEndpoints(client, c.Issuer)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.RefreshToken},
		"client_id":     {c.ClientID},
	}
	resp, err := postForm(client, ep.Token, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session refresh failed: %s: %s — sign in again with `agent-registry login %s`",
			resp.Status, oauthMessage(body), c.Registry)
	}
	fresh, err := credentialFromTokenResponse(&Discovery{
		Issuer:   c.Issuer,
		ClientID: c.ClientID,
		Audience: c.Audience,
		Scopes:   c.Scopes,
		Registry: c.Registry,
	}, body)
	if err != nil {
		return nil, err
	}
	if fresh.RefreshToken == "" {
		fresh.RefreshToken = c.RefreshToken
	}
	fresh.SignedInAt = c.SignedInAt
	return fresh, nil
}

// Logout revokes the refresh token at the issuer. Best-effort: a revocation
// endpoint that is absent or unhappy must not stop the local credential from
// being deleted, which is the part the user actually asked for.
func Logout(client *http.Client, c *Credential) error {
	if c.RefreshToken == "" {
		return nil
	}
	doc, err := oidc.Discover(client, strings.TrimRight(c.Issuer, "/"))
	if err != nil {
		return err
	}
	if doc.EndSessionEndpoint == "" {
		return nil
	}
	resp, err := postForm(client, doc.EndSessionEndpoint, url.Values{
		"client_id":     {c.ClientID},
		"refresh_token": {c.RefreshToken},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("issuer returned %s", resp.Status)
	}
	return nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func credentialFromTokenResponse(d *Discovery, body []byte) (*Credential, error) {
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, errors.New("the issuer returned no access token")
	}
	c := &Credential{
		Registry:     NormalizeRegistry(d.Registry),
		Issuer:       strings.TrimRight(d.Issuer, "/"),
		ClientID:     d.ClientID,
		Audience:     d.Audience,
		Scopes:       d.Scopes,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		SignedInAt:   time.Now().UTC(),
	}
	if tr.ExpiresIn > 0 {
		c.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()
	}
	// Read sub/preferred_username out of the token for display only. The
	// signature is not checked here — the registry is the one that decides
	// whether this token means anything, and it checks properly.
	if _, claimsJSON, _, _, err := token.DecodeSegments(tr.AccessToken); err == nil {
		var claims struct {
			Sub               string          `json:"sub"`
			PreferredUsername string          `json:"preferred_username"`
			Aud               json.RawMessage `json:"aud"`
		}
		if json.Unmarshal(claimsJSON, &claims) == nil {
			c.Subject = claims.Sub
			c.Username = claims.PreferredUsername
			c.Audiences = parseAudience(claims.Aud)
		}
	}
	return c, nil
}

func postForm(client *http.Client, endpoint string, form url.Values) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

func oauthError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error
}

// The reconcile scripts live in the agentic-live-www workspace, not in this
// repository, so every message that names one says where it is. An operator
// who does not have that checkout still gets the setting to change by hand.
const workspaceScripts = "agentic-live-www"

// reconcileHint is the one command that arms a realm for this CLI. Every
// message that names it also says which workspace it lives in, because the
// script is in agentic-live-www and not in this repository — an operator
// without that checkout still needs to know what to change by hand.
func reconcileHint(d *Discovery) string {
	return fmt.Sprintf(
		"    KEYCLOAK_URL=%s KC_BOOTSTRAP_ADMIN_PASSWORD=... \\\n"+
			"      node keycloak/reconcile-cli-client.mjs --client-id %s --audience %s\n"+
			"                                              (in the %s workspace)",
		issuerOrigin(d.Issuer), d.ClientID, d.Audience, workspaceScripts)
}

// redirectSetupHint turns the token-endpoint error that means "this redirect
// URI was never registered" into instructions. Keycloak answers
// invalid_grant/invalid_request with a description mentioning the redirect
// URI; the raw text sends an operator hunting through client settings, and the
// actual fix is one line.
//
// Returns "" for anything else, so a genuine protocol error still surfaces
// verbatim rather than being explained away as a misconfiguration.
func redirectSetupHint(body []byte, d *Discovery, redirect string) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	if !strings.Contains(strings.ToLower(e.Description), "redirect") {
		return ""
	}
	return fmt.Sprintf(
		"Client %q at %s does not accept the redirect URI %s.\n"+
			"Loopback sign-in needs it registered. An administrator adds it once:\n%s",
		d.ClientID, d.Issuer, redirect, reconcileHint(d))
}

// deviceSetupHint turns the OAuth error that means "the realm was never armed
// for this" into instructions, because the raw code sends an operator hunting
// through client settings. Observed on the live realm: the device grant flag
// is an import-time setting, and a realm import does not touch a realm that
// already exists.
//
// Returns "" for anything else, so a genuine protocol error still surfaces
// verbatim rather than being explained away as a misconfiguration.
func deviceSetupHint(body []byte, d *Discovery) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	if e.Error != "unauthorized_client" {
		return ""
	}
	return fmt.Sprintf(
		"%s cannot start a device sign-in: the OAuth 2.0 device grant is disabled on client %q at %s.\n"+
			"An administrator enables it once — in the Keycloak console it is the client\u2019s\n"+
			"\"OAuth 2.0 Device Authorization Grant\" toggle, or:\n%s",
		d.Registry, d.ClientID, d.Issuer, reconcileHint(d))
}

// issuerOrigin reduces a realm URL to the scheme+host the reconcile scripts
// take as KEYCLOAK_URL. Falls back to the input when it will not parse.
func issuerOrigin(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return issuer
	}
	return u.Scheme + "://" + u.Host
}

func oauthMessage(body []byte) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		if e.Description != "" {
			return e.Error + ": " + e.Description
		}
		return e.Error
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

// parseAudience reads the `aud` claim, which JWT allows to be either a single
// string or an array of them.
func parseAudience(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// AudienceSetupHint explains a token that signed in fine but carries no
// audience for this registry. Reachable when the realm client has no audience
// mapper — the sign-in succeeds and only pull time fails, which is the worst
// possible moment to find out, so it is said at sign-in instead.
func AudienceSetupHint(d *Discovery) string {
	return fmt.Sprintf(
		"Client %q at %s mints tokens without the audience %q that %s checks for.\n"+
			"The audience comes from a mapper on the client; without it a sign-in succeeds\n"+
			"but every pull is refused. An administrator adds it once:\n%s",
		d.ClientID, d.Issuer, d.Audience, d.Registry, reconcileHint(d))
}
