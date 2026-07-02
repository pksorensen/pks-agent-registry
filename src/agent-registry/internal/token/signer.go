package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// TTL is the lifetime of registry-minted access tokens. Long enough to cover
// a slow multi-gigabyte transfer, short enough to bound the revocation window
// (tokens are enforced statelessly; see ADR 0003).
const TTL = 30 * time.Minute

// Leeway absorbs clock skew between the registry host and token consumers.
const Leeway = 60 * time.Second

// Access is one granted entry of a registry token, per the Docker
// Distribution token spec ("access" claim).
type Access struct {
	Type    string   `json:"type"` // always "repository"
	Name    string   `json:"name"` // "<owner>/<name>"
	Actions []string `json:"actions"`
}

// Claims is the payload of a registry-minted access token.
type Claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	// Owner is the registry namespace the principal acts as ("" for pull-only
	// federated identities). It drives the {owner} path-segment check on writes.
	Owner  string   `json:"owner,omitempty"`
	Access []Access `json:"access"`
}

// LoadOrCreateSigningKey returns the registry's token-signing key, generating
// and persisting a P-256 key under <dataDir>/token/signing.key on first use.
// The kid is derived from the public key so it stays stable across restarts.
func LoadOrCreateSigningKey(dataDir string) (*ecdsa.PrivateKey, string, error) {
	path := filepath.Join(dataDir, "token", "signing.key")
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, "", fmt.Errorf("token signing key %s: not PEM", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("token signing key %s: %w", path, err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, "", fmt.Errorf("token signing key %s: not an ECDSA key", path)
		}
		kid, err := keyID(key)
		return key, kid, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return nil, "", err
	}
	if _, err := tmp.Write(pemBytes); err == nil {
		err = tmp.Chmod(0o600)
	} else {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, "", err
	}
	kid, err := keyID(key)
	return key, kid, err
}

func keyID(key *ecdsa.PrivateKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])[:16], nil
}

// Mint issues a registry access token for the given subject and grants.
func Mint(key *ecdsa.PrivateKey, kid, iss, service, sub, owner string, access []Access, now time.Time) (jwt string, expiresIn int, issuedAt time.Time, err error) {
	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", 0, time.Time{}, err
	}
	if access == nil {
		access = []Access{}
	}
	now = now.UTC().Truncate(time.Second)
	claims := Claims{
		Iss:    iss,
		Sub:    sub,
		Aud:    service,
		Exp:    now.Add(TTL).Unix(),
		Nbf:    now.Add(-Leeway).Unix(),
		Iat:    now.Unix(),
		Jti:    hex.EncodeToString(jtiRaw),
		Owner:  owner,
		Access: access,
	}
	headerJSON, err := json.Marshal(Header{Alg: "ES256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", 0, time.Time{}, err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	jwt, err = SignES256(headerJSON, claimsJSON, key)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	return jwt, int(TTL.Seconds()), now, nil
}

// Verify validates a registry-minted token and returns its claims.
func Verify(jwt string, pub *ecdsa.PublicKey, iss, service string, now time.Time) (*Claims, error) {
	header, claimsJSON, sigInput, sig, err := DecodeSegments(jwt)
	if err != nil {
		return nil, err
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unexpected alg %q", header.Alg)
	}
	if err := VerifyES256(sigInput, sig, pub); err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrMalformed
	}
	if claims.Iss != iss {
		return nil, fmt.Errorf("unexpected issuer %q", claims.Iss)
	}
	if claims.Aud != service {
		return nil, fmt.Errorf("unexpected audience %q", claims.Aud)
	}
	if now.After(time.Unix(claims.Exp, 0).Add(Leeway)) {
		return nil, errors.New("token expired")
	}
	if now.Before(time.Unix(claims.Nbf, 0).Add(-Leeway)) {
		return nil, errors.New("token not yet valid")
	}
	return &claims, nil
}
