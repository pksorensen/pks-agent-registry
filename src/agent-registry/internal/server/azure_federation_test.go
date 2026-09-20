package server

import (
	"crypto/ecdsa"
	"net/http"
	"testing"

	"github.com/pksorensen/pks-agent-registry/internal/azoidc"
	"github.com/pksorensen/pks-agent-registry/internal/ghoidc/ghoidctest"
	"github.com/pksorensen/pks-agent-registry/internal/store"
	"github.com/pksorensen/pks-agent-registry/internal/token"
)

func newAzureTokenServer(t *testing.T) (*Server, *store.Store, *ghoidctest.Issuer, *ecdsa.PrivateKey) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	key, kid, err := token.LoadOrCreateSigningKey(st.DataDir)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	issuer := ghoidctest.New(t)
	azure := azoidc.New("api://registry.agentics.dk")
	azure.JWKSURL = issuer.JWKSURL
	return New(Config{
		Addr: ":0", AdminToken: "admin-secret", Store: st,
		PublicURL: "https://" + testService, TokenKey: key, TokenKid: kid, Azure: azure,
	}), st, issuer, key
}

func TestTokenAzureManagedIdentityPullFlow(t *testing.T) {
	s, st, issuer, _ := newAzureTokenServer(t)
	const tenantID = "11111111-2222-3333-4444-555555555555"
	const clientID = "ffffffff-1111-2222-3333-444444444444"
	const objectID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	_, err := st.CreateTrustBinding(&store.TrustBinding{
		Kind: store.KindAzure, Issuer: "https://sts.windows.net/" + tenantID + "/",
		TenantID: tenantID, ClientID: clientID, ObjectID: objectID,
		Permissions: &store.Permissions{PullScopes: []string{"agentics/*"}},
	})
	if err != nil {
		t.Fatalf("CreateTrustBinding: %v", err)
	}
	seedRepo(t, st, "agentics", "agentics-www")
	raw := issuer.Mint(t, ghoidctest.TokenOpts{
		Audience: "api://registry.agentics.dk",
		Issuer:   "https://sts.windows.net/" + tenantID + "/",
		Extra:    map[string]any{"tid": tenantID, "oid": objectID, "appid": clientID},
	})
	rec, response := fetchToken(t, s, "oauth2", raw, "repository:agentics/agentics-www:pull")
	if response == nil {
		t.Fatalf("Azure token fetch failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doBearer(t, s, http.MethodGet, "/v2/agentics/agentics-www/manifests/latest", response.Token); rec.Code != http.StatusOK {
		t.Fatalf("bearer pull: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}
