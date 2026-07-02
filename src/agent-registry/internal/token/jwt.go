// Package token implements the minimal JOSE surface the registry needs:
// verifying RS256 signatures (GitHub OIDC tokens) and signing/verifying its
// own ES256 registry access tokens. Hand-rolled on stdlib crypto to keep the
// module dependency-free (see ADR 0003).
package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

var (
	ErrMalformed = errors.New("malformed JWT")
	ErrSignature = errors.New("invalid JWT signature")
)

// Header is the decoded JOSE header of a JWT.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// LooksLikeJWT reports whether s is shaped like a compact-serialized JWT.
// Every JSON JOSE header starts with '{' which base64url-encodes to "eyJ".
func LooksLikeJWT(s string) bool {
	return strings.HasPrefix(s, "eyJ") && strings.Count(s, ".") == 2
}

// DecodeSegments splits a compact JWT and base64url-decodes its parts.
// sigInput is the exact byte string the signature covers (header.claims).
func DecodeSegments(jwt string) (header Header, claimsJSON []byte, sigInput string, sig []byte, err error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return Header{}, nil, "", nil, ErrMalformed
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, nil, "", nil, ErrMalformed
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Header{}, nil, "", nil, ErrMalformed
	}
	claimsJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Header{}, nil, "", nil, ErrMalformed
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Header{}, nil, "", nil, ErrMalformed
	}
	return header, claimsJSON, parts[0] + "." + parts[1], sig, nil
}

// VerifyRS256 checks an RSASSA-PKCS1-v1_5/SHA-256 signature over sigInput.
func VerifyRS256(sigInput string, sig []byte, pub *rsa.PublicKey) error {
	h := sha256.Sum256([]byte(sigInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return ErrSignature
	}
	return nil
}

// SignES256 produces a compact JWT signed with ECDSA P-256/SHA-256. Per JOSE,
// the signature is the raw 64-byte R||S concatenation, not ASN.1 DER.
func SignES256(headerJSON, claimsJSON []byte, key *ecdsa.PrivateKey) (string, error) {
	sigInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyES256 checks a raw R||S ECDSA P-256/SHA-256 signature over sigInput.
func VerifyES256(sigInput string, sig []byte, pub *ecdsa.PublicKey) error {
	if len(sig) != 64 {
		return ErrSignature
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256([]byte(sigInput))
	if !ecdsa.Verify(pub, h[:], r, s) {
		return ErrSignature
	}
	return nil
}
