package handlers

import (
	"context"
	"net/http"

	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/server/httpx"
)

type deleter interface {
	Delete(ctx context.Context, userID uint64, id string) (bool, error)
}

func NewDelete(repo deleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, err := repo.Delete(r.Context(), session.UserID(r.Context()), r.PathValue("id"))
		switch {
		case err != nil:
			httpx.Error(w, http.StatusInternalServerError, "internal")
		case !ok:
			httpx.Error(w, http.StatusNotFound, "not_found")
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
