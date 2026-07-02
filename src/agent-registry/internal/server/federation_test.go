package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

func doAdmin(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestMgmtFederationCRUD(t *testing.T) {
	s, st, _, _ := newTokenServer(t)
	if _, err := st.CreateOwner("ctx", "pw", &store.Permissions{Push: true}); err != nil {
		t.Fatal(err)
	}

	// Create.
	rec := doAdmin(t, s, http.MethodPost, "/_mgmt/federation",
		`{"repository":"context-and/skills-marketplace","environment":"production","pullScopes":["agentics/pks-agent-marketplace"],"createdBy":"poul@kjeldager.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID     string `json:"id"`
		Pinned bool   `json:"pinned"`
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Pinned || created.Issuer == "" {
		t.Fatalf("create response malformed: %s", rec.Body.String())
	}

	// List.
	rec = doAdmin(t, s, http.MethodGet, "/_mgmt/federation", "")
	var list struct {
		Bindings []struct {
			ID          string `json:"id"`
			Repository  string `json:"repository"`
			Environment string `json:"environment"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Bindings) != 1 || list.Bindings[0].Repository != "context-and/skills-marketplace" || list.Bindings[0].Environment != "production" {
		t.Fatalf("list mismatch: %s", rec.Body.String())
	}

	// Get + delete.
	if rec := doAdmin(t, s, http.MethodGet, "/_mgmt/federation/"+created.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", rec.Code)
	}
	if rec := doAdmin(t, s, http.MethodDelete, "/_mgmt/federation/"+created.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", rec.Code)
	}
	if rec := doAdmin(t, s, http.MethodGet, "/_mgmt/federation/"+created.ID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: want 404, got %d", rec.Code)
	}
}

func TestMgmtFederationCreateValidation(t *testing.T) {
	s, _, _, _ := newTokenServer(t)

	// Push binding without owner.
	rec := doAdmin(t, s, http.MethodPost, "/_mgmt/federation", `{"repository":"a/b","push":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("push without owner: want 400, got %d", rec.Code)
	}
	// Push binding with nonexistent owner.
	rec = doAdmin(t, s, http.MethodPost, "/_mgmt/federation", `{"repository":"a/b","push":true,"owner":"ghost"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("push with ghost owner: want 400, got %d", rec.Code)
	}
	// Missing repository.
	rec = doAdmin(t, s, http.MethodPost, "/_mgmt/federation", `{"pullScopes":["agentics/*"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing repository: want 400, got %d", rec.Code)
	}
	// Unauthenticated.
	req := httptest.NewRequest(http.MethodGet, "/_mgmt/federation", nil)
	unauth := httptest.NewRecorder()
	s.ServeHTTP(unauth, req)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("no admin token: want 401, got %d", unauth.Code)
	}
}
