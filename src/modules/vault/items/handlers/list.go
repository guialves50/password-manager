package handlers

import (
	"context"
	"net/http"

	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
	"github.com/guialves50/password-manager/src/server/httpx"
)

type lister interface {
	ListByUser(ctx context.Context, userID uint64) ([]repository.Item, error)
}

func NewList(repo lister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := repo.ListByUser(r.Context(), session.UserID(r.Context()))
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		out := make([]dto.StoredItem, len(items))
		for i, it := range items {
			out[i] = dto.StoredItem{ID: it.ID, Blob: it.Blob}
		}
		httpx.JSON(w, http.StatusOK, out)
	}
}
