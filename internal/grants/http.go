package grants

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Server exposes the grant store over HTTP. It is stateless beyond the
// store, so any number of Server processes can run against one database.
type Server struct {
	store *Store
	mux   *http.ServeMux
}

func NewServer(store *Store) *Server {
	s := &Server{store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /receivers/{receiver}/grants", s.handleCreate)
	mux.HandleFunc("GET /receivers/{receiver}/grants", s.handleList)
	mux.HandleFunc("POST /grants/{grant}/release", s.handleRelease)
	mux.HandleFunc("POST /grants/{grant}/upgrade", s.handleUpgrade)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s.mux = mux
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type createRequest struct {
	Mode string `json:"mode"`
	// RequestKey is the caller-chosen business identifier for this
	// request. Supplying it makes the request idempotent: retries with
	// the same (receiver, request_key) return the one existing grant
	// instead of creating another, and recover its owner token. It is
	// never echoed in listing responses, so it stays a capability of the
	// authorized caller. It is optional; without it the historical
	// one-token-per-create semantics apply.
	RequestKey string `json:"request_key"`
}

// createResponse is the only payload that ever carries the owner token. For
// an idempotent replay it carries the same grant and token the original
// request produced (possibly since released or upgraded), with Replayed set
// so the caller can reconcile an uncertain outcome.
type createResponse struct {
	Grant
	OwnerToken string `json:"owner_token"`
	Replayed   bool   `json:"replayed"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	receiver := r.PathValue("receiver")
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	if req.Mode != ModeShared && req.Mode != ModeExclusive {
		writeError(w, http.StatusBadRequest, "BAD_MODE")
		return
	}
	if len(req.RequestKey) > 256 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST_KEY")
		return
	}
	g, token, replayed, err := s.store.CreateGrant(r.Context(), receiver, req.Mode, req.RequestKey)
	switch {
	case errors.Is(err, ErrBusy):
		writeError(w, http.StatusConflict, "BUSY")
	case errors.Is(err, ErrKeyConflict):
		writeError(w, http.StatusUnprocessableEntity, "REQUEST_KEY_CONFLICT")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "INTERNAL")
	default:
		status := http.StatusCreated
		if replayed {
			status = http.StatusOK
		}
		writeJSON(w, status, createResponse{Grant: g, OwnerToken: token, Replayed: replayed})
	}
}

type listResponse struct {
	Grants []Grant `json:"grants"`
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	grants, err := s.store.ListGrants(r.Context(), r.PathValue("receiver"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL")
		return
	}
	if grants == nil {
		grants = []Grant{}
	}
	writeJSON(w, http.StatusOK, listResponse{Grants: grants})
}

type releaseRequest struct {
	OwnerToken string `json:"owner_token"`
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	var req releaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	g, err := s.store.ReleaseGrant(r.Context(), r.PathValue("grant"), req.OwnerToken)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND")
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "FORBIDDEN")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "INTERNAL")
	default:
		writeJSON(w, http.StatusOK, g)
	}
}

type upgradeRequest struct {
	OwnerToken string `json:"owner_token"`
}

func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	var req upgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	g, err := s.store.UpgradeGrant(r.Context(), r.PathValue("grant"), req.OwnerToken)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND")
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "FORBIDDEN")
	case errors.Is(err, ErrReleased):
		writeError(w, http.StatusConflict, "RELEASED")
	case errors.Is(err, ErrNotShared):
		writeError(w, http.StatusConflict, "NOT_SHARED")
	case errors.Is(err, ErrUpgradePending):
		writeError(w, http.StatusConflict, "UPGRADE_PENDING")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "INTERNAL")
	default:
		writeJSON(w, http.StatusOK, g)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
