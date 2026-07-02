package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// TrustBinding is a federated-identity trust rule: a GitHub repository (and
// optionally one of its environments) that may authenticate with an OIDC
// token instead of a password — the same shape as GitHub/Azure federated
// credentials. Permissions reuse the owner model (ADR 0001); a binding is
// always explicit (never nil = legacy-full).
type TrustBinding struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	// Issuer of the accepted OIDC tokens. Only GitHub Actions today; the field
	// keeps the record extensible to other issuers.
	Issuer string `json:"issuer"`
	// Repository is "org/repo". Used case-insensitively for matching only
	// until the immutable IDs below are pinned.
	Repository string `json:"repository"`
	// RepositoryID / RepositoryOwnerID are GitHub's immutable numeric IDs
	// (serialized as strings in the token claims). Empty until resolved at
	// creation time or pinned on first successful token issuance (TOFU).
	// Once set, matching uses ONLY the IDs — rename-proof.
	RepositoryID      string `json:"repositoryId,omitempty"`
	RepositoryOwnerID string `json:"repositoryOwnerId,omitempty"`
	// Environment restricts the binding to one GitHub environment. Empty
	// accepts any workflow in the repository (Azure-style "entire repo").
	Environment string `json:"environment,omitempty"`
	// Owner is the registry namespace the federated identity acts as.
	// Required when Permissions.Push is set (writes are namespace-bound);
	// empty for pull-only bindings.
	Owner       string       `json:"owner,omitempty"`
	Permissions *Permissions `json:"permissions"`
	CreatedAt   time.Time    `json:"createdAt"`
	CreatedBy   string       `json:"createdBy,omitempty"`
}

// Pinned reports whether the binding has been locked to immutable GitHub IDs.
func (b *TrustBinding) Pinned() bool {
	return b.RepositoryID != ""
}

// Matches reports whether validated token claims satisfy this binding.
// Pinned bindings match exclusively on the immutable IDs; unpinned ones fall
// back to a case-insensitive repository-name match. A configured environment
// must match exactly.
func (b *TrustBinding) Matches(repository, repositoryID, repositoryOwnerID, environment string) bool {
	if b.Pinned() {
		if repositoryID != b.RepositoryID {
			return false
		}
		if b.RepositoryOwnerID != "" && repositoryOwnerID != b.RepositoryOwnerID {
			return false
		}
	} else if !strings.EqualFold(b.Repository, repository) {
		return false
	}
	if b.Environment != "" && environment != b.Environment {
		return false
	}
	return true
}

// PrincipalName is the synthetic identity used as token subject and in logs.
// The ":" prefix guarantees it can never collide with a real owner name
// (ValidName rejects ':').
func (b *TrustBinding) PrincipalName() string {
	return "fed:" + strings.ToLower(b.Repository)
}

func (s *Store) bindingPath(id string) string {
	return filepath.Join(s.DataDir, "federation", id+".json")
}

func validBindingID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// CreateTrustBinding validates and persists a new binding, assigning its ID.
func (s *Store) CreateTrustBinding(b *TrustBinding) (*TrustBinding, error) {
	if b.Repository == "" || strings.Count(b.Repository, "/") != 1 {
		return nil, ErrInvalidName
	}
	if b.Permissions == nil {
		return nil, errors.New("trust binding requires an explicit permissions block")
	}
	if b.Permissions.Push {
		if b.Owner == "" {
			return nil, errors.New("push bindings require an owner namespace")
		}
		if !ValidName(b.Owner) {
			return nil, ErrInvalidName
		}
	}
	if b.Issuer == "" {
		return nil, errors.New("trust binding requires an issuer")
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	stored := *b
	stored.ID = id
	stored.CreatedAt = time.Now().UTC()
	body, err := json.MarshalIndent(&stored, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(s.bindingPath(id), body, 0o600); err != nil {
		return nil, err
	}
	return &stored, nil
}

func (s *Store) GetTrustBinding(id string) (*TrustBinding, error) {
	if !validBindingID(id) {
		return nil, ErrInvalidName
	}
	raw, err := os.ReadFile(s.bindingPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b := &TrustBinding{}
	if err := json.Unmarshal(raw, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ListTrustBindings returns all bindings sorted by creation time then ID.
func (s *Store) ListTrustBindings() ([]*TrustBinding, error) {
	entries, err := os.ReadDir(filepath.Join(s.DataDir, "federation"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]*TrustBinding, 0, len(entries))
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || id == e.Name() {
			continue
		}
		b, err := s.GetTrustBinding(id)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *Store) DeleteTrustBinding(id string) error {
	if !validBindingID(id) {
		return ErrInvalidName
	}
	err := os.Remove(s.bindingPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// PinTrustBinding writes the immutable GitHub IDs onto a binding after the
// first successful, claims-validated token issuance (TOFU). No-op when the
// binding is already pinned.
func (s *Store) PinTrustBinding(id, repositoryID, repositoryOwnerID string) error {
	b, err := s.GetTrustBinding(id)
	if err != nil {
		return err
	}
	if b.Pinned() || repositoryID == "" {
		return nil
	}
	b.RepositoryID = repositoryID
	b.RepositoryOwnerID = repositoryOwnerID
	body, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.bindingPath(id), body, 0o600)
}
