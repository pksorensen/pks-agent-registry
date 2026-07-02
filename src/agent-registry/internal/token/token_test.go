package token

import (
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, kid, err := LoadOrCreateSigningKey(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	return key, kid
}

func TestSigningKeyPersistsAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	k1, kid1, err := LoadOrCreateSigningKey(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	k2, kid2, err := LoadOrCreateSigningKey(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if kid1 != kid2 {
		t.Fatalf("kid changed across loads: %s vs %s", kid1, kid2)
	}
	if !k1.PublicKey.Equal(&k2.PublicKey) {
		t.Fatal("key changed across loads")
	}
}

func TestMintVerifyRoundTrip(t *testing.T) {
	key, kid := newKey(t)
	now := time.Now()
	access := []Access{{Type: "repository", Name: "agentics/app", Actions: []string{"pull"}}}
	jwt, expiresIn, _, err := Mint(key, kid, "agent-registry", "registry.example.com", "fed:ctx/repo", "", access, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if expiresIn != int(TTL.Seconds()) {
		t.Fatalf("expiresIn = %d, want %d", expiresIn, int(TTL.Seconds()))
	}
	claims, err := Verify(jwt, &key.PublicKey, "agent-registry", "registry.example.com", now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "fed:ctx/repo" || len(claims.Access) != 1 || claims.Access[0].Name != "agentics/app" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	key, kid := newKey(t)
	now := time.Now()
	jwt, _, _, err := Mint(key, kid, "iss", "svc", "sub", "", nil, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := Verify(jwt, &key.PublicKey, "iss", "svc", now.Add(TTL+2*Leeway)); err == nil {
		t.Fatal("expected expired-token error")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key, kid := newKey(t)
	jwt, _, _, err := Mint(key, kid, "iss", "svc", "sub", "", nil, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Flip a char in the payload segment.
	parts := strings.Split(jwt, ".")
	payload := []byte(parts[1])
	if payload[10] == 'A' {
		payload[10] = 'B'
	} else {
		payload[10] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]
	if _, err := Verify(tampered, &key.PublicKey, "iss", "svc", time.Now()); err == nil {
		t.Fatal("expected signature error for tampered token")
	}
}

func TestVerifyRejectsWrongAudienceOrIssuer(t *testing.T) {
	key, kid := newKey(t)
	jwt, _, _, err := Mint(key, kid, "iss", "svc", "sub", "", nil, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := Verify(jwt, &key.PublicKey, "iss", "other-service", time.Now()); err == nil {
		t.Fatal("expected audience mismatch error")
	}
	if _, err := Verify(jwt, &key.PublicKey, "other-issuer", "svc", time.Now()); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key, kid := newKey(t)
	other, _ := newKey(t)
	jwt, _, _, err := Mint(key, kid, "iss", "svc", "sub", "", nil, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := Verify(jwt, &other.PublicKey, "iss", "svc", time.Now()); err == nil {
		t.Fatal("expected signature error with wrong key")
	}
}

func TestLooksLikeJWT(t *testing.T) {
	key, kid := newKey(t)
	jwt, _, _, _ := Mint(key, kid, "iss", "svc", "sub", "", nil, time.Now())
	if !LooksLikeJWT(jwt) {
		t.Fatal("real JWT not recognized")
	}
	for _, s := range []string{"password123", "eyJ-not-a-jwt", "a.b.c", ""} {
		if LooksLikeJWT(s) {
			t.Fatalf("%q wrongly recognized as JWT", s)
		}
	}
}
