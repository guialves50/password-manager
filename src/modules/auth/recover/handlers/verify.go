package handlers

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/server/httpx"
)

var derive = keys.Derive

type userStore interface {
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	Attempt(ctx context.Context, id uint64) (bool, error)
	ResetFailures(ctx context.Context, id uint64) error
}

func verify(w http.ResponseWriter, r *http.Request, users userStore, email string, hash []byte, params keys.Params, now time.Time) *user.User {
	ctx := r.Context()
	u, err := users.FindByEmail(ctx, email)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal")
		return nil
	}
	if u == nil {
		salt, _ := keys.Random(16)
		derive(hash, salt, params)
		httpx.Error(w, http.StatusUnauthorized, "invalid_recovery")
		return nil
	}
	if d := u.LockedFor(now); d > 0 {
		httpx.Locked(w, int((d+time.Minute-1)/time.Minute))
		return nil
	}
	ok, err := users.Attempt(ctx, u.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal")
		return nil
	}
	if !ok {
		httpx.Locked(w, int(user.LockDuration/time.Minute))
		return nil
	}
	if subtle.ConstantTimeCompare(derive(hash, u.RecoveryAuthSalt, params), u.RecoveryAuthHash) != 1 {
		httpx.Error(w, http.StatusUnauthorized, "invalid_recovery")
		return nil
	}
	if err := users.ResetFailures(ctx, u.ID); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "internal")
		return nil
	}
	return u
}
