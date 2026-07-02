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
	"github.com/pksorensen/pks-agent-registry/internal/store"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

const testService = "registry.example.com"

// newTokenServer builds a server with the token service armed and a fake
// GitHub OIDC issuer wired in.
func newTokenServer(t *testing.T) (*Server, *store.Store, *ghoidctest.Issuer, *ecdsa.PrivateKey) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	key, kid, err := token.LoadOrCreateSigningKey(st.DataDir)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	iss := ghoidctest.New(t)
	oidc := ghoidc.New(iss.URL, testService)
	oidc.JWKSURL = iss.JWKSURL
	s := New(Config{
		Addr:       ":0",
		AdminToken: "admin-secret",
		Store:      st,
		PublicURL:  "https://" + testService,
		TokenKey:   key,
		TokenKid:   kid,
		OIDC:       oidc,
	})
	return s, st, iss, key
}

type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

// fetchToken hits /token with basic credentials and the given scopes.
func fetchToken(t *testing.T, s *Server, user, pass string, scopes ...string) (*httptest.ResponseRecorder, *tokenResponse) {
	t.Helper()
	url := "/token?service=" + testService
	for _, sc := range scopes {
		url += "&scope=" + sc
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(user, pass)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return rec, nil
	}
	var tr tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil {
		t.Fatalf("token response decode: %v body=%s", err, rec.Body.String())
	}
	return rec, &tr
}

func doBearer(t *testing.T, s *Server, method, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// marketplaceBinding creates the canonical customer binding: pull-only access
// to agentics/pks-agent-marketplace for a GitHub repo.
func marketplaceBinding(t *testing.T, st *store.Store, repo, environment string) *store.TrustBinding {
	t.Helper()
	b, err := st.CreateTrustBinding(&store.TrustBinding{
		Issuer:      ghoidc.DefaultIssuer,
		Repository:  repo,
		Environment: environment,
		Permissions: &store.Permissions{PullScopes: []string{"agentics/pks-agent-marketplace"}},
	})
	if err != nil {
		t.Fatalf("CreateTrustBinding: %v", err)
	}
	return b
}

func TestV2ChallengeAdvertisesBearerAndBasic(t *testing.T) {
	s, _, _, _ := newTokenServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	challenges := rec.Result().Header.Values("WWW-Authenticate")
	if len(challenges) != 2 {
		t.Fatalf("want 2 challenges, got %v", challenges)
	}
	if !strings.HasPrefix(challenges[0], `Bearer realm="https://registry.example.com/token"`) || !strings.Contains(challenges[0], `service="registry.example.com"`) {
		t.Fatalf("bearer challenge malformed: %s", challenges[0])
	}
	if challenges[1] != `Basic realm="registry"` {
		t.Fatalf("basic challenge malformed: %s", challenges[1])
	}
}

// The initial anonymous 401 on a repository route must advertise the pull
// scope so challenge-driven clients (e.g. `az acr import`) request a correctly
// scoped token on the first try rather than a scope-less one that is denied.
func TestAnonymousRepoChallengeCarriesPullScope(t *testing.T) {
	s, _, _, _ := newTokenServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v2/agentics/pks-agent-marketplace/manifests/latest", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	var bearer string
	for _, c := range rec.Result().Header.Values("WWW-Authenticate") {
		if strings.HasPrefix(c, "Bearer ") {
			bearer = c
		}
	}
	if !strings.Contains(bearer, `scope="repository:agentics/pks-agent-marketplace:pull"`) {
		t.Fatalf("anonymous repo challenge missing pull scope: %q", bearer)
	}
}

func TestV2ChallengeBasicOnlyWhenTokenAuthDisarmed(t *testing.T) {
	s, _ := newPermServer(t) // no PublicURL/TokenKey
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	challenges := rec.Result().Header.Values("WWW-Authenticate")
	if len(challenges) != 1 || challenges[0] != `Basic realm="registry"` {
		t.Fatalf("want single Basic challenge, got %v", challenges)
	}
	// And the token endpoint answers 501.
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/token", nil))
	if rec2.Code != http.StatusNotImplemented {
		t.Fatalf("disarmed /token: want 501, got %d", rec2.Code)
	}
}

func TestTokenStaticCredentialIssuesToken(t *testing.T) {
	s, st, _, key := newTokenServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{PullScopes: []string{"agentics/pks-agent-marketplace"}}); err != nil {
		t.Fatal(err)
	}
	rec, tr := fetchToken(t, s, "acme", "pw", "repository:agentics/pks-agent-marketplace:pull")
	if tr == nil {
		t.Fatalf("token fetch failed: %d %s", rec.Code, rec.Body.String())
	}
	if tr.Token != tr.AccessToken || tr.ExpiresIn != int(token.TTL.Seconds()) || tr.IssuedAt == "" {
		t.Fatalf("token response malformed: %+v", tr)
	}
	claims, err := token.Verify(tr.Token, &key.PublicKey, "agent-registry", testService, time.Now())
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Sub != "acme" || claims.Owner != "acme" {
		t.Fatalf("claims identity mismatch: %+v", claims)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "agentics/pks-agent-marketplace" || claims.Access[0].Actions[0] != "pull" {
		t.Fatalf("claims access mismatch: %+v", claims.Access)
	}
}

func TestTokenScopelessLoginProbe(t *testing.T) {
	s, st, _, _ := newTokenServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{}); err != nil {
		t.Fatal(err)
	}
	rec, tr := fetchToken(t, s, "acme", "pw")
	if tr == nil {
		t.Fatalf("scope-less probe failed: %d %s", rec.Code, rec.Body.String())
	}
	// The empty-access token must pass the /v2/ base check (docker login).
	if rec := doBearer(t, s, http.MethodGet, "/v2/", tr.Token); rec.Code != http.StatusOK {
		t.Fatalf("bearer /v2/ base: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// Bad credentials must NOT get a token.
	if rec, _ := fetchToken(t, s, "acme", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad password: want 401, got %d", rec.Code)
	}
}

func TestTokenScopeIntersection(t *testing.T) {
	s, st, _, key := newTokenServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{PullScopes: []string{"agentics/pks-agent-marketplace"}}); err != nil {
		t.Fatal(err)
	}
	_, tr := fetchToken(t, s, "acme", "pw",
		"repository:agentics/pks-agent-marketplace:pull,push", // pull allowed, push not (other ns + no push perm)
		"repository:agentics/secret-tool:pull",                // not in scope
		"repository:acme/own:pull,push",                       // own ns pull ok, push denied (Push=false)
		"registry:catalog:*",                                  // unknown type ignored
	)
	if tr == nil {
		t.Fatal("token fetch failed")
	}
	claims, err := token.Verify(tr.Token, &key.PublicKey, "agent-registry", testService, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, a := range claims.Access {
		got[a.Name] = a.Actions
	}
	if len(got) != 2 {
		t.Fatalf("granted access = %+v, want 2 entries", got)
	}
	if a := got["agentics/pks-agent-marketplace"]; len(a) != 1 || a[0] != "pull" {
		t.Fatalf("marketplace grant = %v, want [pull]", a)
	}
	if a := got["acme/own"]; len(a) != 1 || a[0] != "pull" {
		t.Fatalf("own-ns grant = %v, want [pull]", a)
	}
}

func TestTokenGitHubOIDCPullFlow(t *testing.T) {
	s, st, iss, _ := newTokenServer(t)
	marketplaceBinding(t, st, "context-and/skills-marketplace", "")
	seedRepo(t, st, "agentics", "pks-agent-marketplace")
	seedRepo(t, st, "agentics", "secret-tool")

	jwt := iss.Mint(t, ghoidctest.TokenOpts{
		Audience:          testService,
		Repository:        "context-and/skills-marketplace",
		RepositoryID:      "12345",
		RepositoryOwnerID: "999",
	})
	// Username is irrelevant for OIDC credentials.
	rec, tr := fetchToken(t, s, "oauth2", jwt, "repository:agentics/pks-agent-marketplace:pull")
	if tr == nil {
		t.Fatalf("OIDC token fetch failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doBearer(t, s, http.MethodGet, "/v2/agentics/pks-agent-marketplace/manifests/latest", tr.Token); rec.Code != http.StatusOK {
		t.Fatalf("bearer pull: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Out-of-scope repo is not granted even when requested.
	_, tr2 := fetchToken(t, s, "oauth2", jwt, "repository:agentics/secret-tool:pull")
	if tr2 == nil {
		t.Fatal("token fetch failed")
	}
	if rec := doBearer(t, s, http.MethodGet, "/v2/agentics/secret-tool/manifests/latest", tr2.Token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("out-of-scope bearer pull: want 401, got %d", rec.Code)
	}

	// Wrong audience, expired token, unknown repo → 401 at /token.
	badAud := iss.Mint(t, ghoidctest.TokenOpts{Audience: "elsewhere", Repository: "context-and/skills-marketplace"})
	if rec, _ := fetchToken(t, s, "oauth2", badAud); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong aud: want 401, got %d", rec.Code)
	}
	past := time.Now().Add(-time.Hour)
	expired := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", IssuedAt: past, Expiry: past.Add(5 * time.Minute)})
	if rec, _ := fetchToken(t, s, "oauth2", expired); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired: want 401, got %d", rec.Code)
	}
	unbound := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "someone/else", RepositoryID: "777"})
	if rec, _ := fetchToken(t, s, "oauth2", unbound); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no matching binding: want 401, got %d", rec.Code)
	}
}

func TestTokenBindingEnvironmentEnforced(t *testing.T) {
	s, st, iss, _ := newTokenServer(t)
	marketplaceBinding(t, st, "context-and/skills-marketplace", "production")

	prod := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "1", Environment: "production"})
	if rec, tr := fetchToken(t, s, "oauth2", prod); tr == nil {
		t.Fatalf("production env: want token, got %d", rec.Code)
	}
	staging := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "1", Environment: "staging"})
	if rec, _ := fetchToken(t, s, "oauth2", staging); rec.Code != http.StatusUnauthorized {
		t.Fatalf("staging env: want 401, got %d", rec.Code)
	}
	noEnv := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "1"})
	if rec, _ := fetchToken(t, s, "oauth2", noEnv); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no env: want 401, got %d", rec.Code)
	}
}

func TestTokenBindingTOFUPinsRepositoryID(t *testing.T) {
	s, st, iss, _ := newTokenServer(t)
	b := marketplaceBinding(t, st, "context-and/skills-marketplace", "")

	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "12345", RepositoryOwnerID: "999"})
	if rec, tr := fetchToken(t, s, "oauth2", jwt); tr == nil {
		t.Fatalf("first issuance failed: %d", rec.Code)
	}
	pinned, err := st.GetTrustBinding(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned.Pinned() || pinned.RepositoryID != "12345" || pinned.RepositoryOwnerID != "999" {
		t.Fatalf("binding not TOFU-pinned: %+v", pinned)
	}

	// Renamed repo (same immutable ID) still authenticates.
	renamed := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/new-name", RepositoryID: "12345", RepositoryOwnerID: "999"})
	if rec, tr := fetchToken(t, s, "oauth2", renamed); tr == nil {
		t.Fatalf("renamed repo with pinned ID: want token, got %d", rec.Code)
	}
	// Name squat (same name, different ID) is rejected after pinning.
	squat := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "666", RepositoryOwnerID: "666"})
	if rec, _ := fetchToken(t, s, "oauth2", squat); rec.Code != http.StatusUnauthorized {
		t.Fatalf("name squat: want 401, got %d", rec.Code)
	}
}

func TestBearerInsufficientScopeGets401WithScopeChallenge(t *testing.T) {
	s, st, _, _ := newTokenServer(t)
	if _, err := st.CreateOwner("acme", "pw", &store.Permissions{PullScopes: []string{"agentics/pks-agent-marketplace"}}); err != nil {
		t.Fatal(err)
	}
	seedRepo(t, st, "agentics", "secret-tool")

	// Login-probe token (no access), then hit a repo → 401 + scoped challenge.
	_, tr := fetchToken(t, s, "acme", "pw")
	rec := doBearer(t, s, http.MethodGet, "/v2/agentics/secret-tool/manifests/latest", tr.Token)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer insufficient scope: want 401, got %d", rec.Code)
	}
	found := false
	for _, c := range rec.Result().Header.Values("WWW-Authenticate") {
		if strings.Contains(c, `scope="repository:agentics/secret-tool:pull"`) && strings.Contains(c, "insufficient_scope") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing scoped bearer challenge: %v", rec.Result().Header.Values("WWW-Authenticate"))
	}

	// Same denial via Basic stays a 403 (existing behavior).
	if rec := doAuth(t, s, http.MethodGet, "/v2/agentics/secret-tool/manifests/latest", "acme", "pw"); rec.Code != http.StatusForbidden {
		t.Fatalf("basic out-of-scope: want 403, got %d", rec.Code)
	}
}

func TestRawOIDCJWTAsBasicPasswordOnV2(t *testing.T) {
	s, st, iss, _ := newTokenServer(t)
	marketplaceBinding(t, st, "context-and/skills-marketplace", "")
	seedRepo(t, st, "agentics", "pks-agent-marketplace")

	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "1"})
	if rec := doAuth(t, s, http.MethodGet, "/v2/agentics/pks-agent-marketplace/manifests/latest", "anything", jwt); rec.Code != http.StatusOK {
		t.Fatalf("raw JWT as basic password: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// Static owner passwords still work on the same plane.
	if _, err := st.PutOwner("agentics", "pw"); err != nil {
		t.Fatal(err)
	}
	if rec := doAuth(t, s, http.MethodGet, "/v2/agentics/pks-agent-marketplace/manifests/latest", "agentics", "pw"); rec.Code != http.StatusOK {
		t.Fatalf("static basic after token-auth arming: want 200, got %d", rec.Code)
	}
}

func TestFederatedPushOwnNamespaceOnly(t *testing.T) {
	s, st, iss, _ := newTokenServer(t)
	if _, err := st.CreateOwner("ctx", "pw", &store.Permissions{Push: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateTrustBinding(&store.TrustBinding{
		Issuer:      ghoidc.DefaultIssuer,
		Repository:  "context-and/skills-marketplace",
		Owner:       "ctx",
		Permissions: &store.Permissions{Push: true, PullScopes: []string{"agentics/*"}},
	}); err != nil {
		t.Fatal(err)
	}

	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "1"})
	_, tr := fetchToken(t, s, "oauth2", jwt, "repository:ctx/app:pull,push")
	if tr == nil {
		t.Fatal("push token fetch failed")
	}
	if rec := doBearer(t, s, http.MethodPost, "/v2/ctx/app/blobs/uploads/", tr.Token); rec.Code != http.StatusAccepted {
		t.Fatalf("federated push own ns: want 202, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Push scope on a foreign namespace is never granted.
	_, trForeign := fetchToken(t, s, "oauth2", jwt, "repository:agentics/app:pull,push")
	if rec := doBearer(t, s, http.MethodPost, "/v2/agentics/app/blobs/uploads/", trForeign.Token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("federated push foreign ns: want 401, got %d", rec.Code)
	}

	// A pull-only binding never yields push access, even in "its" namespace.
	s2, st2, iss2, _ := newTokenServer(t)
	if _, err := st2.CreateTrustBinding(&store.TrustBinding{
		Issuer:      ghoidc.DefaultIssuer,
		Repository:  "context-and/other",
		Owner:       "ctx",
		Permissions: &store.Permissions{Push: false, PullScopes: []string{"agentics/*"}},
	}); err != nil {
		t.Fatal(err)
	}
	jwt2 := iss2.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/other", RepositoryID: "2"})
	_, trPullOnly := fetchToken(t, s2, "oauth2", jwt2, "repository:ctx/app:pull,push")
	if rec := doBearer(t, s2, http.MethodPost, "/v2/ctx/app/blobs/uploads/", trPullOnly.Token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pull-only federated push: want 401, got %d", rec.Code)
	}
}

func TestBearerCatalogFilteredByTokenScopes(t *testing.T) {
	s, st, iss, _ := newTokenServer(t)
	marketplaceBinding(t, st, "context-and/skills-marketplace", "")
	seedRepo(t, st, "agentics", "pks-agent-marketplace")
	seedRepo(t, st, "agentics", "secret-tool")

	jwt := iss.Mint(t, ghoidctest.TokenOpts{Audience: testService, Repository: "context-and/skills-marketplace", RepositoryID: "1"})
	_, tr := fetchToken(t, s, "oauth2", jwt, "repository:agentics/pks-agent-marketplace:pull")
	rec := doBearer(t, s, http.MethodGet, "/v2/_catalog", tr.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer catalog: want 200, got %d", rec.Code)
	}
	var got struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Repositories) != 1 || got.Repositories[0] != "agentics/pks-agent-marketplace" {
		t.Fatalf("bearer catalog leaked: %v", got.Repositories)
	}
}
