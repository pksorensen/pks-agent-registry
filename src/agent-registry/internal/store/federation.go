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

// Trust binding kinds. A binding with no Kind is a GitHub Actions binding —
// every record written before ADR 0004 predates the field.
const (
	KindGitHub   = "github"
	KindKeycloak = "keycloak"
	KindAzure    = "azure"
)

// TrustBinding is a federated-identity trust rule: an external identity that
// may authenticate with an OIDC token instead of a password — the same shape
// as GitHub/Azure federated credentials. Permissions reuse the owner model
// (ADR 0001); a binding is always explicit (never nil = legacy-full).
//
// Two kinds exist. A GitHub binding (ADR 0003) trusts a repository, and
// optionally one of its environments, so CI can push without a stored secret.
// A Keycloak binding (ADR 0004) trusts a person — by username, or by any
// member of a group — so a developer can `agent-registry login` instead of
// being handed an owner password.
type TrustBinding struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	// Kind selects which identity fields below are load-bearing. Empty means
	// KindGitHub for records written before the field existed.
	Kind string `json:"kind,omitempty"`
	// Issuer of the accepted OIDC tokens: GitHub Actions, or a Keycloak realm
	// URL ("https://login.agentics.dk/realms/agentics").
	Issuer string `json:"issuer"`

	// --- KindGitHub ---

	// Repository is "org/repo". Used case-insensitively for matching only
	// until the immutable IDs below are pinned.
	Repository string `json:"repository,omitempty"`
	// RepositoryID / RepositoryOwnerID are GitHub's immutable numeric IDs
	// (serialized as strings in the token claims). Empty until resolved at
	// creation time or pinned on first successful token issuance (TOFU).
	// Once set, matching uses ONLY the IDs — rename-proof.
	RepositoryID      string `json:"repositoryId,omitempty"`
	RepositoryOwnerID string `json:"repositoryOwnerId,omitempty"`
	// Environment restricts the binding to one GitHub environment. Empty
	// accepts any workflow in the repository (Azure-style "entire repo").
	Environment string `json:"environment,omitempty"`

	// --- KindKeycloak ---

	// Username matches preferred_username, case-insensitively, until Subject
	// is pinned. Exactly one of Username or Group is set.
	Username string `json:"username,omitempty"`
	// Group matches any member of a Keycloak group. Requires a group-membership
	// mapper on the CLI's own client, which reconcile-cli-client.mjs adds.
	Group string `json:"group,omitempty"`
	// Subject is the Keycloak `sub` UUID, pinned on first successful login of
	// a *username* binding (TOFU) so a later username change cannot hand the
	// binding to someone else. Group bindings are never pinned: they are
	// deliberately open to whoever is in the group.
	Subject string `json:"subject,omitempty"`

	// --- KindAzure ---

	// TenantID, ClientID and ObjectID pin an Azure managed identity to its
	// immutable Entra service principal. All three must match the signed token.
	TenantID string `json:"tenantId,omitempty"`
	ClientID string `json:"clientId,omitempty"`
	ObjectID string `json:"objectId,omitempty"`

	// Owner is the registry namespace the federated identity acts as.
	// Required when Permissions.Push is set (writes are namespace-bound);
	// empty for pull-only bindings.
	Owner       string       `json:"owner,omitempty"`
	Permissions *Permissions `json:"permissions"`
	CreatedAt   time.Time    `json:"createdAt"`
	CreatedBy   string       `json:"createdBy,omitempty"`
}

// KindOf returns the binding's kind, defaulting empty to KindGitHub.
func (b *TrustBinding) KindOf() string {
	if b.Kind == "" {
		return KindGitHub
	}
	return b.Kind
}

// Pinned reports whether the binding has been locked to an immutable ID.
// A group binding has nothing to pin and reports false forever, which is
// correct: it grants to a membership, not to one person.
func (b *TrustBinding) Pinned() bool {
	if b.KindOf() == KindAzure {
		return b.TenantID != "" && b.ClientID != "" && b.ObjectID != ""
	}
	if b.KindOf() == KindKeycloak {
		return b.Subject != ""
	}
	return b.RepositoryID != ""
}

// Pinnable reports whether a first successful login should pin this binding.
func (b *TrustBinding) Pinnable() bool {
	if b.KindOf() == KindAzure {
		return false
	}
	if b.KindOf() == KindKeycloak {
		return b.Username != ""
	}
	return true
}

func (b *TrustBinding) MatchesAzure(tenantID, clientID, objectID string) bool {
	return b.KindOf() == KindAzure &&
		strings.EqualFold(b.TenantID, tenantID) &&
		strings.EqualFold(b.ClientID, clientID) &&
		strings.EqualFold(b.ObjectID, objectID)
}

// Matches reports whether validated GitHub token claims satisfy this binding.
// Pinned bindings match exclusively on the immutable IDs; unpinned ones fall
// back to a case-insensitive repository-name match. A configured environment
// must match exactly.
func (b *TrustBinding) Matches(repository, repositoryID, repositoryOwnerID, environment string) bool {
	if b.KindOf() != KindGitHub {
		return false
	}
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

// MatchesUser reports whether validated Keycloak claims satisfy this binding.
// A pinned username binding matches only its pinned subject; an unpinned one
// matches the username case-insensitively. hasGroup is supplied by the caller
// so this package stays free of claim-shape knowledge.
func (b *TrustBinding) MatchesUser(subject, username string, hasGroup func(string) bool) bool {
	if b.KindOf() != KindKeycloak {
		return false
	}
	if b.Group != "" {
		return hasGroup != nil && hasGroup(b.Group)
	}
	if b.Username == "" {
		return false
	}
	if b.Pinned() {
		return subject != "" && subject == b.Subject
	}
	return strings.EqualFold(b.Username, username)
}

// PrincipalName is the synthetic identity used as token subject and in logs
// for GitHub bindings. The ":" prefix guarantees it can never collide with a
// real owner name (ValidName rejects ':'). Keycloak principals are named after
// the *person* who authenticated, not the binding, so their name is built from
// the token claims instead.
func (b *TrustBinding) PrincipalName() string {
	if b.KindOf() == KindAzure {
		return "azure:" + strings.ToLower(b.ObjectID)
	}
	return "fed:" + strings.ToLower(b.Repository)
}

// Label is the human-readable identity a binding grants to, for listings.
func (b *TrustBinding) Label() string {
	if b.KindOf() == KindAzure {
		return "azure:" + b.ClientID
	}
	if b.KindOf() == KindKeycloak {
		if b.Group != "" {
			return "group:" + b.Group
		}
		return "user:" + b.Username
	}
	if b.Environment != "" {
		return b.Repository + "@" + b.Environment
	}
	return b.Repository
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
	switch b.KindOf() {
	case KindGitHub:
		if b.Repository == "" || strings.Count(b.Repository, "/") != 1 {
			return nil, ErrInvalidName
		}
	case KindKeycloak:
		if (b.Username == "") == (b.Group == "") {
			return nil, errors.New("a keycloak binding needs exactly one of username or group")
		}
	case KindAzure:
		if b.TenantID == "" || b.ClientID == "" || b.ObjectID == "" {
			return nil, errors.New("an azure binding needs tenantId, clientId and objectId")
		}
	default:
		return nil, errors.New("unknown trust binding kind " + b.Kind)
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
	return s.writeBinding(b)
}

// PinTrustBindingSubject locks a Keycloak *username* binding to the subject
// that first used it. Group bindings are left alone — pinning one would hand
// the whole group's grant to whichever member happened to log in first.
func (s *Store) PinTrustBindingSubject(id, subject string) error {
	b, err := s.GetTrustBinding(id)
	if err != nil {
		return err
	}
	if b.Pinned() || subject == "" || !b.Pinnable() {
		return nil
	}
	b.Subject = subject
	return s.writeBinding(b)
}

func (s *Store) writeBinding(b *TrustBinding) error {
	body, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.bindingPath(b.ID), body, 0o600)
}
