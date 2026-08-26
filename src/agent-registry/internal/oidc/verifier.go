// Package oidc is the shared OpenID Connect verification core: JWKS discovery
// and caching, RS256 signature checking, and the issuer/audience/time bounds
// every accepted external token must satisfy.
//
// It knows nothing about *which* issuer it is talking to. The issuer-specific
// packages sit on top and only unmarshal the claims they care about:
// internal/ghoidc for GitHub Actions, internal/kcoidc for Keycloak (ADR 0004).
// Stdlib-only, like the rest of this module (ADR 0003).
package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/token"
)

const (
	jwksCacheTTL       = 6 * time.Hour
	jwksRefetchMinGap  = time.Minute
	validationLeeway   = 60 * time.Second
	jwksFetchTimeout   = 10 * time.Second
	jwksMaxResponseLen = 1 << 20
)

var ErrNoMatchingKey = errors.New("no JWKS key matches token kid")

// Standard are the registered claims Verify enforces. Issuer-specific claims
// are left in the raw JSON for the caller to unmarshal.
type Standard struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"` // string or []string
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf"`
	Iat int64           `json:"iat"`
}

// Verifier validates RS256 tokens from one issuer against its JWKS.
// Zero value is not usable; use NewVerifier.
type Verifier struct {
	IssuerURL string
	Audience  string
	HTTP      *http.Client

	// JWKSURL overrides discovery; tests point it at an httptest server.
	JWKSURL string

	// AudienceCheck replaces the default "aud must contain Audience" rule when
	// set. It receives the full claims JSON, so an issuer-specific validator can
	// accept some other proof that the token was meant for us — internal/kcoidc
	// uses it for the opt-in azp fallback a bare third-party realm needs. A
	// non-nil error rejects the token, exactly as the default rule would.
	AudienceCheck func(claimsJSON []byte) error

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// NewVerifier returns a Verifier for one issuer and one required audience.
func NewVerifier(issuerURL, audience string) *Verifier {
	return &Verifier{IssuerURL: issuerURL, Audience: audience}
}

// Verify checks signature, issuer, audience and time bounds, and returns the
// raw claims JSON so the caller can decode its own claim set.
func (v *Verifier) Verify(rawJWT string, now time.Time) ([]byte, error) {
	header, claimsJSON, sigInput, sig, err := token.DecodeSegments(rawJWT)
	if err != nil {
		return nil, err
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unexpected alg %q (want RS256)", header.Alg)
	}
	pub, err := v.keyFor(header.Kid, now)
	if err != nil {
		return nil, err
	}
	if err := token.VerifyRS256(sigInput, sig, pub); err != nil {
		return nil, err
	}

	var std Standard
	if err := json.Unmarshal(claimsJSON, &std); err != nil {
		return nil, token.ErrMalformed
	}
	if std.Iss != v.IssuerURL {
		return nil, fmt.Errorf("unexpected issuer %q", std.Iss)
	}
	if v.AudienceCheck != nil {
		if err := v.AudienceCheck(claimsJSON); err != nil {
			return nil, err
		}
	} else if !AudienceContains(std.Aud, v.Audience) {
		return nil, fmt.Errorf("token audience does not include %q", v.Audience)
	}
	if std.Exp != 0 && now.After(time.Unix(std.Exp, 0).Add(validationLeeway)) {
		return nil, errors.New("token expired")
	}
	if std.Nbf != 0 && now.Before(time.Unix(std.Nbf, 0).Add(-validationLeeway)) {
		return nil, errors.New("token not yet valid")
	}
	return claimsJSON, nil
}

// UnverifiedIssuer reads the iss claim WITHOUT checking the signature. It
// exists for one purpose: picking which verifier a credential belongs to
// before that verifier validates it. Never make an authorization decision on
// this value — the token is still unauthenticated when it is read.
func UnverifiedIssuer(rawJWT string) string {
	_, claimsJSON, _, _, err := token.DecodeSegments(rawJWT)
	if err != nil {
		return ""
	}
	var std Standard
	if err := json.Unmarshal(claimsJSON, &std); err != nil {
		return ""
	}
	return std.Iss
}

// AudienceContains reports whether a JWT aud claim — a string or an array of
// strings — includes want.
func AudienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 || want == "" {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, a := range list {
			if a == want {
				return true
			}
		}
	}
	return false
}

// keyFor returns the cached public key for kid, refetching the JWKS when the
// cache is stale or the kid is unknown (rate-limited to one attempt/minute so
// garbage kids cannot turn the registry into a JWKS-fetch amplifier).
func (v *Verifier) keyFor(kid string, now time.Time) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	fresh := now.Sub(v.fetchedAt) < jwksCacheTTL
	if pub, ok := v.keys[kid]; ok && fresh {
		return pub, nil
	}
	if now.Sub(v.lastAttempt) < jwksRefetchMinGap {
		if pub, ok := v.keys[kid]; ok {
			return pub, nil // stale but present beats failing hard
		}
		return nil, ErrNoMatchingKey
	}
	v.lastAttempt = now
	keys, err := v.fetchJWKS()
	if err != nil {
		if pub, ok := v.keys[kid]; ok {
			return pub, nil // serve stale on fetch error
		}
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	v.keys = keys
	v.fetchedAt = now
	if pub, ok := v.keys[kid]; ok {
		return pub, nil
	}
	return nil, ErrNoMatchingKey
}

func (v *Verifier) httpClient() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return &http.Client{Timeout: jwksFetchTimeout}
}

func (v *Verifier) fetchJWKS() (map[string]*rsa.PublicKey, error) {
	url := v.JWKSURL
	if url == "" {
		discovered, err := v.discoverJWKSURL()
		if err != nil {
			return nil, err
		}
		url = discovered
	}
	resp, err := v.httpClient().Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %s", resp.Status)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, jwksMaxResponseLen)).Decode(&doc); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contained no usable RSA keys")
	}
	return keys, nil
}

// Discovery returns the issuer's OpenID configuration document, decoded into
// the fields this module uses. The CLI needs the device-authorization and
// token endpoints; the server needs jwks_uri.
type Discovery struct {
	Issuer                      string `json:"issuer"`
	JWKSURI                     string `json:"jwks_uri"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	EndSessionEndpoint          string `json:"end_session_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
}

// Discover fetches <issuerURL>/.well-known/openid-configuration.
func Discover(client *http.Client, issuerURL string) (*Discovery, error) {
	if client == nil {
		client = &http.Client{Timeout: jwksFetchTimeout}
	}
	resp, err := client.Get(issuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openid-configuration returned %s", resp.Status)
	}
	doc := &Discovery{}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, jwksMaxResponseLen)).Decode(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func (v *Verifier) discoverJWKSURL() (string, error) {
	doc, err := Discover(v.httpClient(), v.IssuerURL)
	if err != nil {
		return "", err
	}
	if doc.JWKSURI == "" {
		return "", errors.New("openid-configuration has no jwks_uri")
	}
	return doc.JWKSURI, nil
}
