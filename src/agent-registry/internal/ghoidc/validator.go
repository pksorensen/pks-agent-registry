// Package ghoidc validates GitHub Actions OIDC ID tokens against the GitHub
// issuer's JWKS. Stdlib-only: JWKS is parsed by hand and RS256 verified via
// crypto/rsa (see internal/token for the JOSE primitives).
package ghoidc

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

// DefaultIssuer is the GitHub Actions OIDC issuer.
const DefaultIssuer = "https://token.actions.githubusercontent.com"

const (
	jwksCacheTTL       = 6 * time.Hour
	jwksRefetchMinGap  = time.Minute
	validationLeeway   = 60 * time.Second
	jwksFetchTimeout   = 10 * time.Second
	jwksMaxResponseLen = 1 << 20
)

var ErrNoMatchingKey = errors.New("no JWKS key matches token kid")

// Claims are the GitHub Actions token claims the registry cares about.
// GitHub serves repository_id / repository_owner_id as JSON strings.
type Claims struct {
	Sub               string `json:"sub"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Environment       string `json:"environment"`
	Ref               string `json:"ref"`

	Iss string          `json:"iss"`
	Aud json.RawMessage `json:"aud"` // string or []string
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf"`
	Iat int64           `json:"iat"`
}

// Validator verifies GitHub Actions OIDC tokens. Zero value is not usable;
// set IssuerURL and Audience (New applies defaults).
type Validator struct {
	IssuerURL string
	Audience  string
	HTTP      *http.Client

	// JWKSURL overrides discovery; tests point it at an httptest server.
	JWKSURL string

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

// New returns a Validator for the given audience against the public GitHub
// Actions issuer.
func New(issuerURL, audience string) *Validator {
	if issuerURL == "" {
		issuerURL = DefaultIssuer
	}
	return &Validator{IssuerURL: issuerURL, Audience: audience}
}

// Validate verifies signature, issuer, audience and time bounds of a GitHub
// Actions OIDC token and returns its claims.
func (v *Validator) Validate(rawJWT string, now time.Time) (*Claims, error) {
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

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, token.ErrMalformed
	}
	if claims.Iss != v.IssuerURL {
		return nil, fmt.Errorf("unexpected issuer %q", claims.Iss)
	}
	if !audienceContains(claims.Aud, v.Audience) {
		return nil, fmt.Errorf("token audience does not include %q", v.Audience)
	}
	if claims.Exp != 0 && now.After(time.Unix(claims.Exp, 0).Add(validationLeeway)) {
		return nil, errors.New("token expired")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-validationLeeway)) {
		return nil, errors.New("token not yet valid")
	}
	return &claims, nil
}

func audienceContains(raw json.RawMessage, want string) bool {
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
func (v *Validator) keyFor(kid string, now time.Time) (*rsa.PublicKey, error) {
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

func (v *Validator) httpClient() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return &http.Client{Timeout: jwksFetchTimeout}
}

func (v *Validator) fetchJWKS() (map[string]*rsa.PublicKey, error) {
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

func (v *Validator) discoverJWKSURL() (string, error) {
	resp, err := v.httpClient().Get(v.IssuerURL + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openid-configuration returned %s", resp.Status)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, jwksMaxResponseLen)).Decode(&doc); err != nil {
		return "", err
	}
	if doc.JWKSURI == "" {
		return "", errors.New("openid-configuration has no jwks_uri")
	}
	return doc.JWKSURI, nil
}
