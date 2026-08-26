package server

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pksorensen/pks-agent-registry/internal/ghoidc"
	"github.com/pksorensen/pks-agent-registry/internal/ghoidc/ghoidctest"
	"github.com/pksorensen/pks-agent-registry/internal/kcoidc"
	"github.com/pksorensen/pks-agent-registry/internal/kcoidc/kctest"
	"github.com/pksorensen/pks-agent-registry/internal/store"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

// newKeycloakServer is newTokenServer with interactive sign-in armed as well,
// so both federated credential types are live on the same registry.
func newKeycloakServer(t *testing.T) (*Server, *store.Store, *ghoidctest.Issuer, *kctest.Realm, *ecdsa.PrivateKey) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	key, kid, err := token.LoadOrCreateSigningKey(st.DataDir)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	gh := ghoidctest.New(t)
	ghValidator := ghoidc.New(gh.URL, testService)
	ghValidator.JWKSURL = gh.JWKSURL

	realm := kctest.New(t)
	kc := kcoidc.New(realm.URL, testService)
	kc.JWKSURL = realm.JWKSURL

	s := New(Config{
		Addr:       ":0",
		AdminToken: "admin-secret",
		Store:      st,
		PublicURL:  "https://" + testService,
		TokenKey:   key,
		TokenKid:   kid,
		OIDC:       ghValidator,
		Keycloak:   kc,
		Login: LoginDiscovery{
			Issuer:   realm.URL,
			ClientID: "agent-registry-cli",
			Audience: testService,
			Scopes:   []string{"openid", "offline_access"},
		},
	})
	return s, st, gh, realm, key
}

func TestKeycloakUserBindingPullsAndPins(t *testing.T) {
	s, st, _, realm, _ := newKeycloakServer(t)
	if _, err := st.CreateOwner("agentics", "pw", nil); err != nil {
		t.Fatal(err)
	}
	b, err := st.CreateTrustBinding(&store.TrustBinding{
		Kind:        store.KindKeycloak,
		Issuer:      realm.URL,
		Username:    "poul",
		Permissions: &store.Permissions{PullScopes: []string{"agentics/*"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	jwt := realm.Mint(t, kctest.TokenOpts{
		Audience: []string{"account", testService},
		Subject:  "kc-sub-1",
		Username: "Poul", // Keycloak usernames are matched case-insensitively.
	})
	rec, body := fetchToken(t, s, "oauth2", jwt, "repository:agentics/pks-agent-doorman:pull")
	if rec.Code != http.StatusOK {
		t.Fatalf("token: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	claims, err := token.Verify(body.Token, &s.cfg.TokenKey.PublicKey, tokenIssuer, testService, time.Now())
	if err != nil {
		t.Fatalf("verify minted token: %v", err)
	}
	if claims.Sub != "kc:poul" {
		t.Fatalf("token subject = %q, want kc:poul", claims.Sub)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "agentics/pks-agent-doorman" {
		t.Fatalf("access mismatch: %+v", claims.Access)
	}

	// TOFU: the binding is now locked to the subject that used it.
	after, err := st.GetTrustBinding(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Subject != "kc-sub-1" {
		t.Fatalf("binding subject = %q, want kc-sub-1", after.Subject)
	}

	// A different person who later takes the username no longer matches.
	impostor := realm.Mint(t, kctest.TokenOpts{
		Audience: []string{testService},
		Subject:  "kc-sub-2",
		Username: "poul",
	})
	if rec, _ := fetchToken(t, s, "oauth2", impostor, "repository:agentics/x:pull"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("renamed impostor: want 401, got %d", rec.Code)
	}
}

func TestKeycloakGroupBindingIsNeverPinned(t *testing.T) {
	s, st, _, realm, _ := newKeycloakServer(t)
	b, err := st.CreateTrustBinding(&store.TrustBinding{
		Kind:        store.KindKeycloak,
		Issuer:      realm.URL,
		Group:       "registry-pull",
		Permissions: &store.Permissions{PullScopes: []string{"agentics/*"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Two different members of the group both get through, and the binding is
	// not captured by whichever one arrived first.
	for _, member := range []struct{ sub, user string }{
		{"kc-sub-a", "poul"},
		{"kc-sub-b", "naja"},
	} {
		jwt := realm.Mint(t, kctest.TokenOpts{
			Audience: []string{testService},
			Subject:  member.sub,
			Username: member.user,
			Groups:   []string{"/registry-pull"},
		})
		rec, _ := fetchToken(t, s, "oauth2", jwt, "repository:agentics/pks-agent-git:pull")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d body=%s", member.user, rec.Code, rec.Body.String())
		}
	}
	after, err := st.GetTrustBinding(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Subject != "" {
		t.Fatalf("group binding was pinned to %q — it must stay open to the membership", after.Subject)
	}

	// Someone outside the group is refused.
	outsider := realm.Mint(t, kctest.TokenOpts{
		Audience: []string{testService},
		Subject:  "kc-sub-c",
		Username: "stranger",
	})
	if rec, _ := fetchToken(t, s, "oauth2", outsider, "repository:agentics/pks-agent-git:pull"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-member: want 401, got %d", rec.Code)
	}
}

func TestKeycloakTokenIsNotAcceptedByTheGitHubPath(t *testing.T) {
	s, st, gh, realm, _ := newKeycloakServer(t)
	// A GitHub binding exists; a Keycloak token must not satisfy it, and a
	// GitHub token must not satisfy a Keycloak binding.
	if _, err := st.CreateTrustBinding(&store.TrustBinding{
		Issuer:      gh.URL,
		Repository:  "agentics/thing",
		Permissions: &store.Permissions{PullScopes: []string{"agentics/*"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateTrustBinding(&store.TrustBinding{
		Kind:        store.KindKeycloak,
		Issuer:      realm.URL,
		Username:    "poul",
		Permissions: &store.Permissions{PullScopes: []string{"agentics/*"}},
	}); err != nil {
		t.Fatal(err)
	}

	// Keycloak token, but claiming no group and a username nobody bound.
	stranger := realm.Mint(t, kctest.TokenOpts{Audience: []string{testService}, Username: "stranger"})
	if rec, _ := fetchToken(t, s, "oauth2", stranger, "repository:agentics/thing:pull"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unbound keycloak user: want 401, got %d", rec.Code)
	}

	// GitHub token for a repository that has a binding still works — adding the
	// second credential type must not have disturbed the first.
	ghToken := gh.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "agentics/thing", RepositoryID: "42"})
	if rec, _ := fetchToken(t, s, "oauth2", ghToken, "repository:agentics/thing:pull"); rec.Code != http.StatusOK {
		t.Fatalf("github binding: want 200, got %d", rec.Code)
	}
}

func TestProtectedResourceMetadataDocument(t *testing.T) {
	s, _, _, realm, _ := newKeycloakServer(t)
	req := httptest.NewRequest(http.MethodGet, wellKnownPRM, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var doc protectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != realm.URL {
		t.Fatalf("authorization_servers mismatch: %+v", doc)
	}
	if doc.ClientID != "agent-registry-cli" {
		t.Fatalf("client_id mismatch: %+v", doc)
	}
	// The resource identifier is what the CLI derives the required audience
	// from, so it has to name the registry and not the realm.
	if doc.Resource == "" || !strings.Contains(doc.Resource, testService) {
		t.Fatalf("resource must identify this registry, got %q", doc.Resource)
	}
	if len(doc.ScopesSupported) == 0 {
		t.Fatal("the document must name the scopes to request — the CLI carries no list of its own")
	}
}

// The discovery chain starts at a 401 from the API, so the challenge has to
// carry the pointer. Without it a client that arrived from a bare `docker
// pull` has no way to find the sign-in at all.
func TestChallengeAdvertisesResourceMetadata(t *testing.T) {
	s, _, _, _, _ := newKeycloakServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v2/agentics/thing/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	var bearer string
	for _, h := range rec.Header().Values("WWW-Authenticate") {
		if strings.HasPrefix(h, "Bearer ") {
			bearer = h
		}
	}
	if !strings.Contains(bearer, `resource_metadata="`) {
		t.Fatalf("Bearer challenge carries no resource_metadata: %q", bearer)
	}
	if !strings.Contains(bearer, wellKnownPRM) {
		t.Fatalf("resource_metadata does not point at the PRM document: %q", bearer)
	}
}

func TestProtectedResourceMetadataIs404WhenNotConfigured(t *testing.T) {
	// The plain token server has no Keycloak configured.
	s, _, _, _ := newTokenServer(t)
	req := httptest.NewRequest(http.MethodGet, wellKnownPRM, nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestMgmtCreatesKeycloakBindingWithRegistryIssuer(t *testing.T) {
	s, _, _, realm, _ := newKeycloakServer(t)
	rec := doAdmin(t, s, http.MethodPost, "/_mgmt/federation",
		`{"kind":"keycloak","username":"poul","pullScopes":["agentics/*"],"issuer":"https://evil.example.com/realms/x"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var created store.TrustBinding
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	// The caller's issuer is ignored: bindings can only ever point at the realm
	// this registry itself trusts.
	if created.Issuer != realm.URL {
		t.Fatalf("issuer = %q, want the registry's own realm %q", created.Issuer, realm.URL)
	}
	if created.Username != "poul" || created.KindOf() != store.KindKeycloak {
		t.Fatalf("binding mismatch: %+v", created)
	}

	// Neither-or-both is a bad request.
	if rec := doAdmin(t, s, http.MethodPost, "/_mgmt/federation", `{"kind":"keycloak"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty keycloak binding: want 400, got %d", rec.Code)
	}
	if rec := doAdmin(t, s, http.MethodPost, "/_mgmt/federation", `{"kind":"keycloak","username":"a","group":"b"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("username+group: want 400, got %d", rec.Code)
	}
}
