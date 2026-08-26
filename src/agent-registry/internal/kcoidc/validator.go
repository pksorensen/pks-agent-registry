// Package kcoidc validates Keycloak-issued access tokens so a human can
// authenticate to the registry with the same account they use everywhere else
// (ADR 0004). Signature, issuer, audience and time bounds are the shared
// internal/oidc core; this package adds the claims a person is identified by.
//
// This is a second accepted *credential type* at GET /token, not a delegation
// of the Docker token realm to Keycloak — that remains ours (ADR 0003).
package kcoidc

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/oidc"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

// Claims are the Keycloak token claims the registry cares about.
//
// groups is not a default Keycloak claim — it needs a group-membership mapper
// on the CLI's own client (keycloak/reconcile-cli-client.mjs adds one). Without
// the mapper, group bindings simply never match and username bindings still
// work, which is why the script adds it rather than leaving it to be noticed.
type Claims struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	AuthorizedParty   string   `json:"azp"`
	Groups            []string `json:"groups"`
}

// Identity is the name a Keycloak-authenticated principal is known by in
// tokens and logs. The "kc:" prefix cannot collide with a real owner name
// (store.ValidName rejects ':').
func (c *Claims) Identity() string {
	name := c.PreferredUsername
	if name == "" {
		name = c.Sub
	}
	return "kc:" + strings.ToLower(name)
}

// HasGroup reports whether the token carries the given group. Keycloak writes
// group paths with a leading slash when the mapper's "full path" option is on,
// so both spellings are accepted, case-insensitively.
func (c *Claims) HasGroup(want string) bool {
	want = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(want)), "/")
	if want == "" {
		return false
	}
	for _, g := range c.Groups {
		if strings.TrimPrefix(strings.ToLower(g), "/") == want {
			return true
		}
	}
	return false
}

// Validator verifies Keycloak tokens. The embedded verifier carries
// IssuerURL, Audience, HTTP and the JWKSURL test override.
type Validator struct {
	*oidc.Verifier
}

// New returns a Validator for one realm issuer URL — the full
// "<keycloak>/realms/<realm>" form — and the audience the token must carry.
//
// The audience is the whole confused-deputy defence. Our realm mints tokens
// for several resources from the same account, so without it a token minted
// for anything else and later replayed here would authenticate perfectly: the
// signature, the issuer and the user are all genuine, and only `aud` says
// which resource the user meant it for.
func New(issuerURL, audience string) *Validator {
	return &Validator{Verifier: oidc.NewVerifier(strings.TrimRight(issuerURL, "/"), audience)}
}

// AcceptAuthorizedParty arms the opt-in fallback: a token whose `aud` omits
// this registry is still accepted when its `azp` equals clientID.
//
// This exists for a bare third-party realm, where nobody has added an audience
// mapper and `aud` is whatever the authorization server felt like. It is off
// unless an operator sets REGISTRY_KEYCLOAK_ACCEPT_AZP, and it must stay off by
// default, because it accepts precisely the token the audience is there to
// reject — one minted for another resource by a client we happen to recognise.
// Passing "" is a no-op, so the caller does not need its own guard.
func (v *Validator) AcceptAuthorizedParty(clientID string) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return
	}
	audience := v.Audience
	v.AudienceCheck = func(claimsJSON []byte) error {
		var c struct {
			Aud json.RawMessage `json:"aud"`
			AZP string          `json:"azp"`
		}
		if err := json.Unmarshal(claimsJSON, &c); err != nil {
			return token.ErrMalformed
		}
		if oidc.AudienceContains(c.Aud, audience) {
			return nil
		}
		if c.AZP == clientID {
			return nil
		}
		return fmt.Errorf("token audience does not include %q and azp is not %q", audience, clientID)
	}
}

// Validate verifies the token and returns its claims.
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
