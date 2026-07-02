package ghoidc_test

import (
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/ghoidc"
	"github.com/pksorensen/pks-agent-registry/internal/ghoidc/ghoidctest"
)

const aud = "registry.example.com"

func newValidator(iss *ghoidctest.Issuer) *ghoidc.Validator {
	v := ghoidc.New(iss.URL, aud)
	v.JWKSURL = iss.JWKSURL
	return v
}

func TestValidateHappyPath(t *testing.T) {
	iss := ghoidctest.New(t)
	v := newValidator(iss)
	jwt := iss.Mint(t, ghoidctest.TokenOpts{
		Audience:          aud,
		Repository:        "context-and/skills-marketplace",
		RepositoryID:      "12345",
		RepositoryOwnerID: "999",
		Environment:       "production",
	})
	claims, err := v.Validate(jwt, time.Now())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Repository != "context-and/skills-marketplace" || claims.RepositoryID != "12345" || claims.Environment != "production" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestValidateAudienceArray(t *testing.T) {
	iss := ghoidctest.New(t)
	v := newValidator(iss)
	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: []string{"other", aud}, Repository: "a/b"})
	if _, err := v.Validate(jwt, time.Now()); err != nil {
		t.Fatalf("Validate with aud array: %v", err)
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	iss := ghoidctest.New(t)
	v := newValidator(iss)
	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: "someone-else", Repository: "a/b"})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected audience error")
	}
}

func TestValidateRejectsWrongIssuer(t *testing.T) {
	iss := ghoidctest.New(t)
	v := newValidator(iss)
	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: aud, Repository: "a/b", Issuer: "https://evil.example.com"})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected issuer error")
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	iss := ghoidctest.New(t)
	v := newValidator(iss)
	past := time.Now().Add(-time.Hour)
	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: aud, Repository: "a/b", IssuedAt: past, Expiry: past.Add(5 * time.Minute)})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestValidateRejectsAlgConfusion(t *testing.T) {
	iss := ghoidctest.New(t)
	v := newValidator(iss)
	for _, alg := range []string{"none", "ES256", "HS256"} {
		jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: aud, Repository: "a/b", Alg: alg})
		if _, err := v.Validate(jwt, time.Now()); err == nil {
			t.Fatalf("expected rejection for alg %q", alg)
		}
	}
}

func TestValidateRejectsUnknownKid(t *testing.T) {
	iss := ghoidctest.New(t)
	v := newValidator(iss)
	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: aud, Repository: "a/b", Kid: "nonexistent-kid"})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected unknown-kid error")
	}
}

func TestValidateRejectsForeignKey(t *testing.T) {
	iss := ghoidctest.New(t)
	other := ghoidctest.New(t)
	v := newValidator(iss)
	// Token signed by a different issuer's key but claiming our kid and issuer.
	jwt := other.Mint(t, ghoidctest.TokenOpts{Audience: aud, Repository: "a/b", Kid: iss.Kid, Issuer: iss.URL})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected signature error for foreign key")
	}
}

func TestJWKSDiscoveryViaOpenIDConfiguration(t *testing.T) {
	iss := ghoidctest.New(t)
	v := ghoidc.New(iss.URL, aud) // no JWKSURL override — must discover
	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: aud, Repository: "a/b"})
	if _, err := v.Validate(jwt, time.Now()); err != nil {
		t.Fatalf("Validate via discovery: %v", err)
	}
}
