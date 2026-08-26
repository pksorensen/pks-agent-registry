// Package ghoidc validates GitHub Actions OIDC ID tokens against the GitHub
// issuer's JWKS. The signature, issuer, audience and time checks live in
// internal/oidc; this package only adds GitHub's own claims (ADR 0003).
package ghoidc

import (
	"encoding/json"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/oidc"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

// DefaultIssuer is the GitHub Actions OIDC issuer.
const DefaultIssuer = "https://token.actions.githubusercontent.com"

// ErrNoMatchingKey is returned when the token's kid is absent from the JWKS.
var ErrNoMatchingKey = oidc.ErrNoMatchingKey

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
}

// Validator verifies GitHub Actions OIDC tokens. The embedded verifier
// carries IssuerURL, Audience, HTTP and the JWKSURL test override.
type Validator struct {
	*oidc.Verifier
}

// New returns a Validator for the given audience against the public GitHub
// Actions issuer.
func New(issuerURL, audience string) *Validator {
	if issuerURL == "" {
		issuerURL = DefaultIssuer
	}
	return &Validator{Verifier: oidc.NewVerifier(issuerURL, audience)}
}

// Validate verifies signature, issuer, audience and time bounds of a GitHub
// Actions OIDC token and returns its claims.
func (v *Validator) Validate(rawJWT string, now time.Time) (*Claims, error) {
	claimsJSON, err := v.Verify(rawJWT, now)
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, token.ErrMalformed
	}
	return &claims, nil
}
