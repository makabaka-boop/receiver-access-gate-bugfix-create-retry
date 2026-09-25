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
	// RequestID optionally identifies the business request for
	// idempotent replay; the Idempotency-Key header takes precedence
	// when both are sent.
	RequestID string `json:"request_id"`
}

// createResponse is the only payload that ever carries the owner token:
// the create itself and its idempotent replays to the same request key.
type createResponse struct {
	Grant
	OwnerToken string `json:"owner_token"`
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
	// A caller that keys its request can retry it safely: the committed
	// outcome — grant id and owner token — is replayed to the same key,
	// even if the original response was lost after commit.
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		key = req.RequestID
	}
	if len(key) > 256 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	g, token, err := s.store.CreateGrant(r.Context(), receiver, req.Mode, key)
	switch {
	case errors.Is(err, ErrBusy):
		writeError(w, http.StatusConflict, "BUSY")
	case errors.Is(err, ErrRequestMismatch):
		writeError(w, http.StatusConflict, "REQUEST_MISMATCH")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "INTERNAL")
	default:
		writeJSON(w, http.StatusCreated, createResponse{Grant: g, OwnerToken: token})
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
