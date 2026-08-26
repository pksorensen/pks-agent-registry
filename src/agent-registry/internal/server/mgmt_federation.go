package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pksorensen/pks-agent-registry/internal/ghoidc"
	"github.com/pksorensen/pks-agent-registry/internal/store"
)

type bindingView struct {
	*store.TrustBinding
	Pinned bool `json:"pinned"`
}

func toBindingView(b *store.TrustBinding) bindingView {
	return bindingView{TrustBinding: b, Pinned: b.Pinned()}
}

func (s *Server) handleMgmtFederationList(w http.ResponseWriter, r *http.Request) {
	bindings, err := s.cfg.Store.ListTrustBindings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]bindingView, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, toBindingView(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": out})
}

type bindingCreateReq struct {
	Description string `json:"description,omitempty"`
	// Kind is "github" (default, back-compatible) or "keycloak".
	Kind              string   `json:"kind,omitempty"`
	Repository        string   `json:"repository,omitempty"`
	RepositoryID      string   `json:"repositoryId,omitempty"`
	RepositoryOwnerID string   `json:"repositoryOwnerId,omitempty"`
	Environment       string   `json:"environment,omitempty"`
	Username          string   `json:"username,omitempty"`
	Group             string   `json:"group,omitempty"`
	Owner             string   `json:"owner,omitempty"`
	Push              bool     `json:"push"`
	PullScopes        []string `json:"pullScopes,omitempty"`
	CreatedBy         string   `json:"createdBy,omitempty"`
}

func (s *Server) handleMgmtFederationCreate(w http.ResponseWriter, r *http.Request) {
	var req bindingCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = store.KindGitHub
	}
	issuer := ghoidc.DefaultIssuer
	switch kind {
	case store.KindGitHub:
		if req.Repository == "" {
			http.Error(w, "repository required", http.StatusBadRequest)
			return
		}
	case store.KindKeycloak:
		// The issuer is the registry's own configured realm, never something
		// the caller supplies: an admin token must not be able to point a
		// binding at an issuer this registry does not otherwise trust.
		if s.cfg.Keycloak == nil {
			http.Error(w, "interactive sign-in is not configured (REGISTRY_KEYCLOAK_ISSUER unset)", http.StatusBadRequest)
			return
		}
		issuer = s.cfg.Keycloak.IssuerURL
	default:
		http.Error(w, "unknown binding kind", http.StatusBadRequest)
		return
	}
	if req.Push {
		if req.Owner == "" {
			http.Error(w, "push bindings require an owner namespace", http.StatusBadRequest)
			return
		}
		if _, err := s.cfg.Store.GetOwner(req.Owner); err != nil {
			http.Error(w, "owner namespace does not exist", http.StatusBadRequest)
			return
		}
	}
	b, err := s.cfg.Store.CreateTrustBinding(&store.TrustBinding{
		Description:       req.Description,
		Kind:              req.Kind,
		Issuer:            issuer,
		Repository:        req.Repository,
		RepositoryID:      req.RepositoryID,
		RepositoryOwnerID: req.RepositoryOwnerID,
		Environment:       req.Environment,
		Username:          req.Username,
		Group:             req.Group,
		Owner:             req.Owner,
		Permissions:       &store.Permissions{Push: req.Push, PullScopes: req.PullScopes},
		CreatedBy:         req.CreatedBy,
	})
	if errors.Is(err, store.ErrInvalidName) {
		http.Error(w, "invalid repository, username or owner name", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, toBindingView(b))
}

func (s *Server) handleMgmtFederationGet(w http.ResponseWriter, r *http.Request) {
	b, err := s.cfg.Store.GetTrustBinding(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalidName) {
		http.Error(w, "trust binding not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toBindingView(b))
}

func (s *Server) handleMgmtFederationDelete(w http.ResponseWriter, r *http.Request) {
	err := s.cfg.Store.DeleteTrustBinding(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalidName) {
		http.Error(w, "trust binding not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
