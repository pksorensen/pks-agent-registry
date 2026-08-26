// Package kctest provides a fake Keycloak realm for tests: an httptest
// discovery + JWKS endpoint and a helper that mints RS256 access tokens with
// the claims the registry reads.
package kctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Realm is a fake Keycloak realm.
type Realm struct {
	// URL is the issuer URL tokens carry in iss.
	URL     string
	JWKSURL string
	Key     *rsa.PrivateKey
	Kid     string

	server *httptest.Server
}

// New starts a fake realm with a fresh RSA key. Closed via t.Cleanup.
func New(t *testing.T) *Realm {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	r := &Realm{Key: key, Kid: "kc-test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, _ *http.Request) {
		pub := &r.Key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": r.Kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                        r.URL,
			"jwks_uri":                      r.JWKSURL,
			"token_endpoint":                r.URL + "/protocol/openid-connect/token",
			"device_authorization_endpoint": r.URL + "/protocol/openid-connect/auth/device",
			"authorization_endpoint":        r.URL + "/protocol/openid-connect/auth",
			"end_session_endpoint":          r.URL + "/protocol/openid-connect/logout",
		})
	})
	r.server = httptest.NewServer(mux)
	t.Cleanup(r.server.Close)
	r.URL = r.server.URL
	r.JWKSURL = r.server.URL + "/protocol/openid-connect/certs"
	return r
}

// TokenOpts describe the claims of a minted fake Keycloak access token.
type TokenOpts struct {
	Audience any // string or []string; defaults to "test-audience"
	Subject  string
	Username string
	Email    string
	Groups   []string
	IssuedAt time.Time // defaults to now
	Expiry   time.Time // defaults to IssuedAt+5m
	Kid      string    // defaults to the realm kid
	Alg      string    // defaults to RS256
	Issuer   string    // defaults to the fake realm URL
	// AuthorizedParty is the azp claim — which client obtained the token.
	// Defaults to "agent-registry-cli".
	AuthorizedParty string
}

// Mint signs a Keycloak-shaped access token.
func (r *Realm) Mint(t *testing.T, o TokenOpts) string {
	t.Helper()
	if o.IssuedAt.IsZero() {
		o.IssuedAt = time.Now()
	}
	if o.Expiry.IsZero() {
		o.Expiry = o.IssuedAt.Add(5 * time.Minute)
	}
	if o.Audience == nil {
		o.Audience = "test-audience"
	}
	if o.Kid == "" {
		o.Kid = r.Kid
	}
	if o.Alg == "" {
		o.Alg = "RS256"
	}
	if o.Issuer == "" {
		o.Issuer = r.URL
	}
	if o.Subject == "" {
		o.Subject = "00000000-0000-0000-0000-000000000001"
	}
	if o.AuthorizedParty == "" {
		o.AuthorizedParty = "agent-registry-cli"
	}
	claims := map[string]any{
		"iss":                o.Issuer,
		"aud":                o.Audience,
		"sub":                o.Subject,
		"preferred_username": o.Username,
		"email":              o.Email,
		"azp":                o.AuthorizedParty,
		"iat":                o.IssuedAt.Unix(),
		"nbf":                o.IssuedAt.Unix(),
		"exp":                o.Expiry.Unix(),
	}
	if len(o.Groups) > 0 {
		claims["groups"] = o.Groups
	}
	headerJSON, _ := json.Marshal(map[string]string{"alg": o.Alg, "typ": "JWT", "kid": o.Kid})
	claimsJSON, _ := json.Marshal(claims)
	sigInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.Key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign fake token: %v", err)
	}
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
