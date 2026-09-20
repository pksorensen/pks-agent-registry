// Package azoidc validates Microsoft Entra access tokens issued to Azure
// managed identities. The registry accepts these tokens only when an explicit
// Azure trust binding matches the tenant, object and client identifiers.
package azoidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/oidc"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

const DefaultJWKSURL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

var tenantIDPattern = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)

type Claims struct {
	Sub      string `json:"sub"`
	ObjectID string `json:"oid"`
	ClientID string `json:"appid"`
	AZP      string `json:"azp"`
	TenantID string `json:"tid"`
}

func (c *Claims) EffectiveClientID() string {
	if c.ClientID != "" {
		return c.ClientID
	}
	return c.AZP
}

func (c *Claims) Identity() string {
	return "azure:" + strings.ToLower(c.ObjectID)
}

type Validator struct {
	Audience string
	JWKSURL  string
	HTTP     *http.Client

	mu        sync.Mutex
	verifiers map[string]*oidc.Verifier
}

func New(audience string) *Validator {
	return &Validator{Audience: audience, JWKSURL: DefaultJWKSURL, verifiers: map[string]*oidc.Verifier{}}
}

func tenantFromIssuer(issuer string) string {
	var tenant string
	switch {
	case strings.HasPrefix(issuer, "https://sts.windows.net/"):
		tenant = strings.TrimSuffix(strings.TrimPrefix(issuer, "https://sts.windows.net/"), "/")
	case strings.HasPrefix(issuer, "https://login.microsoftonline.com/") && strings.HasSuffix(issuer, "/v2.0"):
		tenant = strings.TrimSuffix(strings.TrimPrefix(issuer, "https://login.microsoftonline.com/"), "/v2.0")
	}
	if !tenantIDPattern.MatchString(tenant) {
		return ""
	}
	return strings.ToLower(tenant)
}

func IsIssuer(issuer string) bool {
	return tenantFromIssuer(issuer) != ""
}

func (v *Validator) verifier(issuer string) *oidc.Verifier {
	v.mu.Lock()
	defer v.mu.Unlock()
	if verifier := v.verifiers[issuer]; verifier != nil {
		return verifier
	}
	verifier := oidc.NewVerifier(issuer, v.Audience)
	verifier.JWKSURL = v.JWKSURL
	verifier.HTTP = v.HTTP
	v.verifiers[issuer] = verifier
	return verifier
}

func (v *Validator) Validate(rawJWT string, now time.Time) (*Claims, error) {
	issuer := oidc.UnverifiedIssuer(rawJWT)
	tenantID := tenantFromIssuer(issuer)
	if tenantID == "" {
		return nil, errors.New("unsupported Microsoft Entra issuer")
	}
	claimsJSON, err := v.verifier(issuer).Verify(rawJWT, now)
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, token.ErrMalformed
	}
	if !strings.EqualFold(claims.TenantID, tenantID) || claims.ObjectID == "" || claims.EffectiveClientID() == "" {
		return nil, token.ErrMalformed
	}
	return &claims, nil
}
