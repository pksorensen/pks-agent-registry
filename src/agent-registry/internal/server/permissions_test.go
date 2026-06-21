package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

// newPermServer builds a server with no trusted-proxy bypass (so every request
// is credential-authorized) and returns the backing store for seeding.
func newPermServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return New(Config{Addr: ":0", Store: st}), st
}

func seedRepo(t *testing.T, st *store.Store, owner, name string) {
	t.Helper()
	if _, err := st.PutManifest(owner, name, "latest", "application/vnd.oci.image.manifest.v1+json", []byte(`{}`)); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

func doAuth(t *testing.T, s *Server, method, path, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.SetBasicAuth(user, pass)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestLegacyOwnerKeepsFullAccess(t *testing.T) {
	s, st := newPermServer(t)
	// Legacy owner: created via PutOwner → nil Permissions.
	if _, err := st.PutOwner("agentics", "pw"); err != nil {
		t.Fatal(err)
	}
	seedRepo(t, st, "agentics", "pks-agent-marketplace")
	seedRepo(t, st, "other", "thing")

	// Can pull its own and other namespaces.
	if rec := doAuth(t, s, http.MethodGet, "/v2/agentics/pks-agent-marketplace/manifests/latest", "agentics", "pw"); rec.Code != http.StatusOK {
		t.Fatalf("legacy own pull: want 200, got %d", rec.Code)
	}
	if rec := doAuth(t, s, http.MethodGet, "/v2/other/thing/manifests/latest", "agentics", "pw"); rec.Code != http.StatusOK {
		t.Fatalf("legacy cross pull: want 200, got %d", rec.Code)
	}
	// Can push to its own namespace.
	if rec := doAuth(t, s, http.MethodPost, "/v2/agentics/newrepo/blobs/uploads/", "agentics", "pw"); rec.Code != http.StatusAccepted {
		t.Fatalf("legacy push own: want 202, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPullOnlyOwnerCannotPush(t *testing.T) {
	s, st := newPermServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{Push: false, PullScopes: []string{"agentics/pks-agent-marketplace"}}); err != nil {
		t.Fatal(err)
	}
	// Push to its OWN namespace is refused because Push=false.
	rec := doAuth(t, s, http.MethodPost, "/v2/acme/foo/blobs/uploads/", "acme", "pw")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("pull-only push: want 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPushOwnerCanPushOwnButNotOthers(t *testing.T) {
	s, st := newPermServer(t)
	if _, err := st.CreateOwner("pusher", "pw", &store.Permissions{Push: true}); err != nil {
		t.Fatal(err)
	}
	if rec := doAuth(t, s, http.MethodPost, "/v2/pusher/app/blobs/uploads/", "pusher", "pw"); rec.Code != http.StatusAccepted {
		t.Fatalf("push own: want 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := doAuth(t, s, http.MethodPost, "/v2/agentics/app/blobs/uploads/", "pusher", "pw"); rec.Code != http.StatusForbidden {
		t.Fatalf("push other ns: want 403, got %d", rec.Code)
	}
}

func TestScopedPullEnforced(t *testing.T) {
	s, st := newPermServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{Push: false, PullScopes: []string{"agentics/pks-agent-marketplace"}}); err != nil {
		t.Fatal(err)
	}
	seedRepo(t, st, "agentics", "pks-agent-marketplace")
	seedRepo(t, st, "agentics", "secret-tool")
	seedRepo(t, st, "other", "thing")
	seedRepo(t, st, "acme", "private")

	cases := []struct {
		path string
		want int
	}{
		{"/v2/agentics/pks-agent-marketplace/manifests/latest", http.StatusOK}, // in scope
		{"/v2/agentics/secret-tool/manifests/latest", http.StatusForbidden},    // same owner, not in scope
		{"/v2/other/thing/manifests/latest", http.StatusForbidden},             // different owner
		{"/v2/acme/private/manifests/latest", http.StatusOK},                   // own namespace always readable
	}
	for _, c := range cases {
		if rec := doAuth(t, s, http.MethodGet, c.path, "acme", "pw"); rec.Code != c.want {
			t.Fatalf("GET %s: want %d, got %d body=%s", c.path, c.want, rec.Code, rec.Body.String())
		}
	}
}

func TestWildcardScope(t *testing.T) {
	s, st := newPermServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{PullScopes: []string{"agentics/*"}}); err != nil {
		t.Fatal(err)
	}
	seedRepo(t, st, "agentics", "pks-agent-marketplace")
	seedRepo(t, st, "agentics", "secret-tool")
	seedRepo(t, st, "other", "thing")

	if rec := doAuth(t, s, http.MethodGet, "/v2/agentics/secret-tool/manifests/latest", "acme", "pw"); rec.Code != http.StatusOK {
		t.Fatalf("agentics/* should allow secret-tool: got %d", rec.Code)
	}
	if rec := doAuth(t, s, http.MethodGet, "/v2/other/thing/manifests/latest", "acme", "pw"); rec.Code != http.StatusForbidden {
		t.Fatalf("agentics/* should NOT allow other/thing: got %d", rec.Code)
	}
}

func TestCatalogFilteredByScope(t *testing.T) {
	s, st := newPermServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{PullScopes: []string{"agentics/pks-agent-marketplace"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutOwner("agentics", "pw"); err != nil {
		t.Fatal(err)
	}
	seedRepo(t, st, "agentics", "pks-agent-marketplace")
	seedRepo(t, st, "agentics", "secret-tool")
	seedRepo(t, st, "other", "thing")
	seedRepo(t, st, "acme", "private")

	// Scoped owner sees only in-scope + own namespace.
	rec := doAuth(t, s, http.MethodGet, "/v2/_catalog", "acme", "pw")
	if rec.Code != http.StatusOK {
		t.Fatalf("catalog: want 200, got %d", rec.Code)
	}
	var got struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"agentics/pks-agent-marketplace": true, "acme/private": true}
	if len(got.Repositories) != len(want) {
		t.Fatalf("scoped catalog = %v, want keys %v", got.Repositories, want)
	}
	for _, r := range got.Repositories {
		if !want[r] {
			t.Fatalf("scoped catalog leaked %q (full=%v)", r, got.Repositories)
		}
	}

	// Legacy owner sees everything.
	recAll := doAuth(t, s, http.MethodGet, "/v2/_catalog", "agentics", "pw")
	var all struct {
		Repositories []string `json:"repositories"`
	}
	_ = json.Unmarshal(recAll.Body.Bytes(), &all)
	if len(all.Repositories) != 4 {
		t.Fatalf("legacy catalog should see all 4 repos, got %v", all.Repositories)
	}
}

func TestPasswordRotationPreservesPermissions(t *testing.T) {
	_, st := newPermServer(t)
	perms := &store.Permissions{Push: false, PullScopes: []string{"agentics/pks-agent-marketplace"}}
	if _, err := st.CreateOwner("acme", "pw", perms); err != nil {
		t.Fatal(err)
	}
	// Rotate password via PutOwner (the password-reset path).
	if _, err := st.PutOwner("acme", "newpw"); err != nil {
		t.Fatal(err)
	}
	o, err := st.GetOwner("acme")
	if err != nil {
		t.Fatal(err)
	}
	if o.Permissions == nil || o.Permissions.Push || len(o.Permissions.PullScopes) != 1 {
		t.Fatalf("rotation dropped permissions: %+v", o.Permissions)
	}
	if !st.CheckPassword("acme", "newpw") {
		t.Fatal("new password not set")
	}
}
