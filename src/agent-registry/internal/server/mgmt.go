package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pksorensen/pks-agent-registry/internal/store"
)

type ownerView struct {
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

func (s *Server) handleMgmtOwnersList(w http.ResponseWriter, r *http.Request) {
	names, err := s.cfg.Store.ListOwners()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]ownerView, 0, len(names))
	for _, n := range names {
		o, err := s.cfg.Store.GetOwner(n)
		if err != nil {
			continue
		}
		out = append(out, ownerView{Name: o.Name, CreatedAt: o.CreatedAt.Format("2006-01-02T15:04:05Z")})
	}
	writeJSON(w, http.StatusOK, map[string]any{"owners": out})
}

type ownerCreateReq struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (s *Server) handleMgmtOwnerCreate(w http.ResponseWriter, r *http.Request) {
	var req ownerCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Password == "" {
		http.Error(w, "name and password required", http.StatusBadRequest)
		return
	}
	o, err := s.cfg.Store.PutOwner(req.Name, req.Password)
	if errors.Is(err, store.ErrInvalidName) {
		http.Error(w, "invalid owner name", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, ownerView{Name: o.Name, CreatedAt: o.CreatedAt.Format("2006-01-02T15:04:05Z")})
}

func (s *Server) handleMgmtOwnerDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.cfg.Store.DeleteOwner(name); errors.Is(err, store.ErrNotFound) {
		http.Error(w, "owner not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type passwordReq struct {
	Password string `json:"password"`
}

func (s *Server) handleMgmtOwnerPassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req passwordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, "password required", http.StatusBadRequest)
		return
	}
	if _, err := s.cfg.Store.GetOwner(name); errors.Is(err, store.ErrNotFound) {
		http.Error(w, "owner not found", http.StatusNotFound)
		return
	}
	if _, err := s.cfg.Store.PutOwner(name, req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMgmtReposList(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	var (
		repos []string
		err   error
	)
	if owner != "" {
		repos, err = s.cfg.Store.ListReposByOwner(owner)
	} else {
		repos, err = s.cfg.Store.ListRepos()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": repos})
}

func (s *Server) handleMgmtRepoDelete(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	name := r.PathValue("name")
	if err := s.cfg.Store.DeleteRepo(owner, name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMgmtTagsList(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	name := r.PathValue("name")
	tags, err := s.cfg.Store.ListTags(owner, name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repository": owner + "/" + name,
		"tags":       tags,
	})
}

func (s *Server) handleMgmtTagDelete(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	name := r.PathValue("name")
	tag := r.PathValue("tag")
	if err := s.cfg.Store.DeleteTag(owner, name, tag); errors.Is(err, store.ErrNotFound) {
		http.Error(w, "tag not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMgmtGC(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.cfg.Store.GC()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted, "count": len(deleted)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
