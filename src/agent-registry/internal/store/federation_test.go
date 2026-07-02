package store

import (
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

func validBinding() *TrustBinding {
	return &TrustBinding{
		Issuer:      "https://token.actions.githubusercontent.com",
		Repository:  "context-and/skills-marketplace",
		Permissions: &Permissions{PullScopes: []string{"agentics/pks-agent-marketplace"}},
	}
}

func TestTrustBindingCRUD(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateTrustBinding(validBinding())
	if err != nil {
		t.Fatalf("CreateTrustBinding: %v", err)
	}
	if created.ID == "" || created.CreatedAt.IsZero() {
		t.Fatalf("missing id/createdAt: %+v", created)
	}
	got, err := s.GetTrustBinding(created.ID)
	if err != nil {
		t.Fatalf("GetTrustBinding: %v", err)
	}
	if got.Repository != created.Repository {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	list, err := s.ListTrustBindings()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListTrustBindings: %v len=%d", err, len(list))
	}
	if err := s.DeleteTrustBinding(created.ID); err != nil {
		t.Fatalf("DeleteTrustBinding: %v", err)
	}
	if _, err := s.GetTrustBinding(created.ID); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := s.DeleteTrustBinding(created.ID); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound on double delete, got %v", err)
	}
}

func TestTrustBindingValidation(t *testing.T) {
	s := newTestStore(t)
	b := validBinding()
	b.Repository = "no-slash"
	if _, err := s.CreateTrustBinding(b); err == nil {
		t.Fatal("expected error for repository without slash")
	}
	b = validBinding()
	b.Permissions = nil
	if _, err := s.CreateTrustBinding(b); err == nil {
		t.Fatal("expected error for nil permissions")
	}
	b = validBinding()
	b.Permissions = &Permissions{Push: true}
	if _, err := s.CreateTrustBinding(b); err == nil {
		t.Fatal("expected error for push binding without owner")
	}
	b = validBinding()
	b.Permissions = &Permissions{Push: true}
	b.Owner = "Invalid Owner!"
	if _, err := s.CreateTrustBinding(b); err == nil {
		t.Fatal("expected error for push binding with invalid owner name")
	}
	b = validBinding()
	b.Issuer = ""
	if _, err := s.CreateTrustBinding(b); err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestTrustBindingMatching(t *testing.T) {
	cases := []struct {
		name    string
		binding TrustBinding
		repo    string
		repoID  string
		ownerID string
		env     string
		want    bool
	}{
		{"unpinned name match", TrustBinding{Repository: "Org/Repo"}, "org/repo", "1", "2", "", true},
		{"unpinned name mismatch", TrustBinding{Repository: "org/repo"}, "org/other", "1", "2", "", false},
		{"pinned id match, renamed repo", TrustBinding{Repository: "org/old-name", RepositoryID: "1", RepositoryOwnerID: "2"}, "org/new-name", "1", "2", "", true},
		{"pinned rejects name squat", TrustBinding{Repository: "org/repo", RepositoryID: "1", RepositoryOwnerID: "2"}, "org/repo", "666", "2", "", false},
		{"pinned rejects owner-id mismatch", TrustBinding{Repository: "org/repo", RepositoryID: "1", RepositoryOwnerID: "2"}, "org/repo", "1", "666", "", false},
		{"environment required and matching", TrustBinding{Repository: "org/repo", Environment: "production"}, "org/repo", "1", "2", "production", true},
		{"environment required, token has none", TrustBinding{Repository: "org/repo", Environment: "production"}, "org/repo", "1", "2", "", false},
		{"environment required, wrong env", TrustBinding{Repository: "org/repo", Environment: "production"}, "org/repo", "1", "2", "staging", false},
		{"no environment restriction accepts any", TrustBinding{Repository: "org/repo"}, "org/repo", "1", "2", "staging", true},
	}
	for _, tc := range cases {
		if got := tc.binding.Matches(tc.repo, tc.repoID, tc.ownerID, tc.env); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPinTrustBinding(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateTrustBinding(validBinding())
	if err != nil {
		t.Fatalf("CreateTrustBinding: %v", err)
	}
	if err := s.PinTrustBinding(created.ID, "12345", "999"); err != nil {
		t.Fatalf("PinTrustBinding: %v", err)
	}
	got, _ := s.GetTrustBinding(created.ID)
	if !got.Pinned() || got.RepositoryID != "12345" || got.RepositoryOwnerID != "999" {
		t.Fatalf("binding not pinned: %+v", got)
	}
	// Re-pinning with different IDs must be a no-op (already pinned).
	if err := s.PinTrustBinding(created.ID, "666", "666"); err != nil {
		t.Fatalf("re-pin: %v", err)
	}
	got, _ = s.GetTrustBinding(created.ID)
	if got.RepositoryID != "12345" {
		t.Fatalf("re-pin overwrote pinned ID: %+v", got)
	}
}

func TestPrincipalNameCannotCollideWithOwner(t *testing.T) {
	b := TrustBinding{Repository: "Org/Repo"}
	name := b.PrincipalName()
	if name != "fed:org/repo" {
		t.Fatalf("PrincipalName = %q", name)
	}
	if ValidName(name) {
		t.Fatal("principal name must never be a valid owner name")
	}
}
