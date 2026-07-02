// Package ghoidctest provides a fake GitHub Actions OIDC issuer for tests:
// an httptest JWKS endpoint plus helpers to mint RS256 tokens with arbitrary
// claims. Used by both the ghoidc unit tests and the server e2e tests.
package ghoidctest

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

// Issuer is a fake GitHub OIDC issuer.
type Issuer struct {
	// URL is the issuer URL tokens carry in iss (the httptest server base).
	URL string
	// JWKSURL serves the key set.
	JWKSURL string
	Key     *rsa.PrivateKey
	Kid     string

	server *httptest.Server
}

// New starts a fake issuer with a fresh RSA key. Closed via t.Cleanup.
func New(t *testing.T) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	iss := &Issuer{Key: key, Kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		iss.writeJWKS(w)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": iss.JWKSURL})
	})
	iss.server = httptest.NewServer(mux)
	t.Cleanup(iss.server.Close)
	iss.URL = iss.server.URL
	iss.JWKSURL = iss.server.URL + "/.well-known/jwks"
	return iss
}

func (i *Issuer) writeJWKS(w http.ResponseWriter) {
	pub := &i.Key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": i.Kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// TokenOpts describe the claims of a minted fake GitHub token.
type TokenOpts struct {
	Audience          any // string or []string; defaults to "test-audience"
	Repository        string
	RepositoryID      string
	RepositoryOwner   string
	RepositoryOwnerID string
	Environment       string
	IssuedAt          time.Time // defaults to now
	Expiry            time.Time // defaults to IssuedAt+5m
	Kid               string    // defaults to issuer kid
	Alg               string    // defaults to RS256
	Issuer            string    // defaults to the fake issuer URL
}

// Mint signs a GitHub-shaped OIDC token.
func (i *Issuer) Mint(t *testing.T, o TokenOpts) string {
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
		o.Kid = i.Kid
	}
	if o.Alg == "" {
		o.Alg = "RS256"
	}
	if o.Issuer == "" {
		o.Issuer = i.URL
	}
	sub := "repo:" + o.Repository + ":ref:refs/heads/main"
	if o.Environment != "" {
		sub = "repo:" + o.Repository + ":environment:" + o.Environment
	}
	claims := map[string]any{
		"iss":                 o.Issuer,
		"aud":                 o.Audience,
		"sub":                 sub,
		"repository":          o.Repository,
		"repository_id":       o.RepositoryID,
		"repository_owner":    o.RepositoryOwner,
		"repository_owner_id": o.RepositoryOwnerID,
		"iat":                 o.IssuedAt.Unix(),
		"nbf":                 o.IssuedAt.Unix(),
		"exp":                 o.Expiry.Unix(),
	}
	if o.Environment != "" {
		claims["environment"] = o.Environment
	}
	headerJSON, _ := json.Marshal(map[string]string{"alg": o.Alg, "typ": "JWT", "kid": o.Kid})
	claimsJSON, _ := json.Marshal(claims)
	sigInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.Key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign fake token: %v", err)
	}
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
