package kcoidc_test

import (
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/kcoidc"
	"github.com/pksorensen/pks-agent-registry/internal/kcoidc/kctest"
)

const aud = "registry.example.com"

func newValidator(r *kctest.Realm) *kcoidc.Validator {
	v := kcoidc.New(r.URL, aud)
	v.JWKSURL = r.JWKSURL
	return v
}

func TestValidateReadsIdentity(t *testing.T) {
	realm := kctest.New(t)
	v := newValidator(realm)
	jwt := realm.Mint(t, kctest.TokenOpts{
		Audience: []string{"account", aud},
		Subject:  "sub-123",
		Username: "Poul",
		Groups:   []string{"/registry-pull"},
	})
	claims, err := v.Validate(jwt, time.Now())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Sub != "sub-123" || claims.PreferredUsername != "Poul" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if got := claims.Identity(); got != "kc:poul" {
		t.Fatalf("Identity() = %q", got)
	}
}

func TestHasGroupIgnoresLeadingSlashAndCase(t *testing.T) {
	c := &kcoidc.Claims{Groups: []string{"/Registry-Pull"}}
	for _, want := range []string{"registry-pull", "/registry-pull", "Registry-Pull"} {
		if !c.HasGroup(want) {
			t.Fatalf("HasGroup(%q) = false", want)
		}
	}
	if c.HasGroup("other") || c.HasGroup("") {
		t.Fatal("HasGroup matched something it should not")
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	realm := kctest.New(t)
	v := newValidator(realm)
	// The default Keycloak access token carries only "account" — exactly the
	// case the registry-audience client scope exists to fix.
	jwt := realm.Mint(t, kctest.TokenOpts{Audience: "account", Username: "poul"})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected audience error")
	}
}

func TestValidateRejectsForeignRealm(t *testing.T) {
	realm := kctest.New(t)
	other := kctest.New(t)
	v := newValidator(realm)
	jwt := other.Mint(t, kctest.TokenOpts{Audience: aud, Username: "poul", Kid: realm.Kid, Issuer: realm.URL})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected signature error for a token signed by another realm")
	}
}

func TestValidateRejectsAlgConfusion(t *testing.T) {
	realm := kctest.New(t)
	v := newValidator(realm)
	for _, alg := range []string{"none", "ES256", "HS256"} {
		jwt := realm.Mint(t, kctest.TokenOpts{Audience: aud, Username: "poul", Alg: alg})
		if _, err := v.Validate(jwt, time.Now()); err == nil {
			t.Fatalf("expected rejection for alg %q", alg)
		}
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	realm := kctest.New(t)
	v := newValidator(realm)
	past := time.Now().Add(-time.Hour)
	jwt := realm.Mint(t, kctest.TokenOpts{Audience: aud, Username: "poul", IssuedAt: past, Expiry: past.Add(5 * time.Minute)})
	if _, err := v.Validate(jwt, time.Now()); err == nil {
		t.Fatal("expected expiry error")
	}
}

// The audience is the confused-deputy defence, so the case that must fail is a
// token that is genuine in every other way: real signature, real issuer, real
// user, minted by a client this registry recognises — just for somewhere else.
func TestAudienceIsRequiredEvenForAKnownClient(t *testing.T) {
	realm := kctest.New(t)
	v := newValidator(realm)

	replayed := realm.Mint(t, kctest.TokenOpts{
		Audience:        []string{"account"},
		Username:        "poul",
		AuthorizedParty: "agent-registry-cli",
	})
	if _, err := v.Validate(replayed, time.Now()); err == nil {
		t.Fatal("a token minted for another resource was accepted — the audience check is not doing its job")
	}
}

// ...and the same token is accepted once, and only once, an operator has
// deliberately relaxed the check for a realm with no audience mapper.
func TestAcceptAuthorizedPartyIsOptIn(t *testing.T) {
	realm := kctest.New(t)
	noAudience := realm.Mint(t, kctest.TokenOpts{
		Audience:        []string{"account"},
		Username:        "poul",
		AuthorizedParty: "agent-registry-cli",
	})

	// Passing "" must not arm anything: the caller hands us whatever the
	// environment variable held, and empty means unset.
	off := newValidator(realm)
	off.AcceptAuthorizedParty("")
	if _, err := off.Validate(noAudience, time.Now()); err == nil {
		t.Fatal("AcceptAuthorizedParty(\"\") armed the fallback")
	}

	on := newValidator(realm)
	on.AcceptAuthorizedParty("agent-registry-cli")
	if _, err := on.Validate(noAudience, time.Now()); err != nil {
		t.Fatalf("armed fallback rejected a matching azp: %v", err)
	}

	// Even armed, it is a narrower door and not an open one: another client's
	// token still has no business here.
	other := realm.Mint(t, kctest.TokenOpts{
		Audience:        []string{"account"},
		Username:        "poul",
		AuthorizedParty: "some-other-cli",
	})
	if _, err := on.Validate(other, time.Now()); err == nil {
		t.Fatal("the armed fallback accepted an unrelated client")
	}

	// A correct audience keeps working regardless of azp.
	proper := realm.Mint(t, kctest.TokenOpts{
		Audience:        []string{aud},
		Username:        "poul",
		AuthorizedParty: "some-other-cli",
	})
	if _, err := on.Validate(proper, time.Now()); err != nil {
		t.Fatalf("armed fallback broke the ordinary audience path: %v", err)
	}
}
