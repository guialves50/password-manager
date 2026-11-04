package session

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/guialves50/password-manager/src/server/httpx"
)

type toucher interface {
	Touch(ctx context.Context, token string, now time.Time) (uint64, bool, error)
}

type ctxKey struct{}

func Require(store toucher, now func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || token == "" {
				httpx.Error(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			id, ok, err := store.Touch(r.Context(), token, now())
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "internal")
				return
			}
			if !ok {
				httpx.Error(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
		})
	}
}

func UserID(ctx context.Context) uint64 {
	id, _ := ctx.Value(ctxKey{}).(uint64)
	return id
}
