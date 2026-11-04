package handlers

import (
	"context"
	"net/http"
	"regexp"

	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
	"github.com/guialves50/password-manager/src/server/httpx"
)

const MaxBlob = 48 << 10

var validID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type creator interface {
	Create(ctx context.Context, it *repository.Item) error
}

func NewCreate(repo creator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in dto.StoredItem
		if !httpx.Decode(w, r, &in) {
			return
		}
		if !validID.MatchString(in.ID) || len(in.Blob) == 0 || len(in.Blob) > MaxBlob {
			httpx.Error(w, http.StatusBadRequest, "invalid_request")
			return
		}
		it := &repository.Item{ID: in.ID, UserID: session.UserID(r.Context()), Blob: in.Blob}
		if err := repo.Create(r.Context(), it); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}
