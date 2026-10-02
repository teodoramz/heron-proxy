package handlers

import (
	"errors"
	"net/http"

	"github.com/amzteodor/heron/internal/api/auth"
	"github.com/amzteodor/heron/internal/store"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login authenticates a user and issues session cookies.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := h.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		// Hash anyway so a missing account and a wrong password cost the same.
		_, _ = auth.VerifyPassword(req.Password, dummyHash)
		writeError(w, http.StatusUnauthorized, "that username and password do not match an account")
		return
	}
	ok, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !ok || !user.Enabled {
		writeError(w, http.StatusUnauthorized, "that username and password do not match an account")
		return
	}
	csrf, err := h.Auth.SetSessionCookies(w, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.Store.TouchLogin(r.Context(), user.ID)
	_ = h.Store.Audit(r.Context(), user.ID, "auth.login", map[string]string{"username": user.Username})

	writeJSON(w, http.StatusOK, map[string]any{
		"user":       user,
		"csrf_token": csrf,
	})
}

// dummyHash is a valid argon2id hash used to equalize timing on unknown emails.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// Logout clears the session cookies.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.Auth.ClearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the authenticated user and their app scope.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	s := session(r)
	writeJSON(w, http.StatusOK, map[string]any{"user": s.User, "apps": s.Apps})
}

type userRequest struct {
	Username string     `json:"username"`
	Password string     `json:"password"`
	Role     store.Role `json:"role"`
	Enabled  bool       `json:"enabled"`
	Apps     []string   `json:"apps"`
}

// ListUsers returns every account.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// CreateUser adds an account.
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := store.ValidUsername(req.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Password) < 12 {
		writeError(w, http.StatusBadRequest, "the password must be at least 12 characters")
		return
	}
	if !req.Role.Valid() {
		writeError(w, http.StatusBadRequest, "role must be admin or analyst")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user, err := h.Store.CreateUser(r.Context(), req.Username, hash, req.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Apps) > 0 {
		if err := h.Store.SetAppAccess(r.Context(), user.ID, req.Apps); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	h.audit(r, "user.create", map[string]any{"user_id": user.ID, "username": user.Username, "role": req.Role})
	writeJSON(w, http.StatusCreated, user)
}

// ChangeOwnPassword lets the signed-in person change their own password. It
// needs the current one, so a borrowed session cannot lock the owner out.
func (h *Handler) ChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.NewPassword) < 12 {
		writeError(w, http.StatusBadRequest, "the new password must be at least 12 characters")
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeError(w, http.StatusBadRequest, "the new password is the same as the current one")
		return
	}

	me := session(r).User
	user, err := h.Store.GetUser(r.Context(), me.ID)
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	ok, err := auth.VerifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil || !ok {
		writeError(w, http.StatusForbidden, "the current password is not correct")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.Store.SetPassword(r.Context(), user.ID, hash); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	h.audit(r, "user.password", map[string]any{"user_id": user.ID, "username": user.Username})
	w.WriteHeader(http.StatusNoContent)
}

// UpdateUser changes a role, enabled state, password or app scope.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req userRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Role != "" {
		if err := h.Store.UpdateUser(r.Context(), id, req.Role, req.Enabled); err != nil {
			writeError(w, statusFor(err), err.Error())
			return
		}
	}
	if req.Password != "" {
		if len(req.Password) < 12 {
			writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := h.Store.SetPassword(r.Context(), id, hash); err != nil {
			writeError(w, statusFor(err), err.Error())
			return
		}
	}
	if req.Apps != nil {
		if err := h.Store.SetAppAccess(r.Context(), id, req.Apps); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	h.audit(r, "user.update", map[string]any{"user_id": id})
	w.WriteHeader(http.StatusNoContent)
}

// DeleteUser removes an account. An admin cannot delete themselves.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == session(r).User.ID {
		writeError(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	if err := h.Store.DeleteUser(r.Context(), id); err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	h.audit(r, "user.delete", map[string]any{"user_id": id})
	w.WriteHeader(http.StatusNoContent)
}

// ListAudit returns recent audit entries.
func (h *Handler) ListAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := h.Store.ListAudit(r.Context(), intParam(r, "limit", 100))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func statusFor(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}
