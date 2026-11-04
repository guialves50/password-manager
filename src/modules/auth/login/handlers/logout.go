package handlers

import (
	"context"
	"net/http"

	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/server/httpx"
)

type deleter interface {
	Delete(ctx context.Context, token string) error
}

func NewLogout(sessions deleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := session.Token(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if err := sessions.Delete(r.Context(), token); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
