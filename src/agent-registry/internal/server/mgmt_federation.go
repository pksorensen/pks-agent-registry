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
	Description       string   `json:"description,omitempty"`
	Repository        string   `json:"repository"`
	RepositoryID      string   `json:"repositoryId,omitempty"`
	RepositoryOwnerID string   `json:"repositoryOwnerId,omitempty"`
	Environment       string   `json:"environment,omitempty"`
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
	if req.Repository == "" {
		http.Error(w, "repository required", http.StatusBadRequest)
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
		Issuer:            ghoidc.DefaultIssuer,
		Repository:        req.Repository,
		RepositoryID:      req.RepositoryID,
		RepositoryOwnerID: req.RepositoryOwnerID,
		Environment:       req.Environment,
		Owner:             req.Owner,
		Permissions:       &store.Permissions{Push: req.Push, PullScopes: req.PullScopes},
		CreatedBy:         req.CreatedBy,
	})
	if errors.Is(err, store.ErrInvalidName) {
		http.Error(w, "invalid repository or owner name", http.StatusBadRequest)
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
