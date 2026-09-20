package azoidc_test

import (
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/azoidc"
	"github.com/pksorensen/pks-agent-registry/internal/ghoidc/ghoidctest"
)

const (
	tenantID = "11111111-2222-3333-4444-555555555555"
	audience = "api://registry.agentics.dk"
)

func TestManagedIdentityToken(t *testing.T) {
	issuer := ghoidctest.New(t)
	validator := azoidc.New(audience)
	validator.JWKSURL = issuer.JWKSURL

	raw := issuer.Mint(t, ghoidctest.TokenOpts{
		Audience: audience,
		Issuer:   "https://sts.windows.net/" + tenantID + "/",
		Extra: map[string]any{
			"tid":   tenantID,
			"oid":   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"appid": "ffffffff-1111-2222-3333-444444444444",
		},
	})

	claims, err := validator.Validate(raw, time.Now())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.TenantID != tenantID || claims.EffectiveClientID() != "ffffffff-1111-2222-3333-444444444444" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestManagedIdentityTokenRejectsWrongAudience(t *testing.T) {
	issuer := ghoidctest.New(t)
	validator := azoidc.New(audience)
	validator.JWKSURL = issuer.JWKSURL
	raw := issuer.Mint(t, ghoidctest.TokenOpts{
		Audience: "api://someone-else",
		Issuer:   "https://sts.windows.net/" + tenantID + "/",
		Extra: map[string]any{
			"tid": tenantID, "oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "appid": "ffffffff-1111-2222-3333-444444444444",
		},
	})
	if _, err := validator.Validate(raw, time.Now()); err == nil {
		t.Fatal("expected audience validation error")
	}
}
