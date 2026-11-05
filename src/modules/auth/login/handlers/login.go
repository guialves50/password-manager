package handlers

import (
	"cmp"
	"context"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/auth/totp"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/server/httpx"
)

var derive = keys.Derive

type userStore interface {
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	Attempt(ctx context.Context, id uint64) (bool, error)
	ResetFailures(ctx context.Context, id uint64) error
	TOTPAccept(ctx context.Context, id uint64, counter int64) (bool, error)
}

type sessionStore interface {
	Create(ctx context.Context, userID uint64, now time.Time) (string, error)
	PurgeExpired(ctx context.Context, now time.Time) error
}

func NewLogin(users userStore, sessions sessionStore, check *totp.Checker, params keys.Params, now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in dto.Request
		if !httpx.Decode(w, r, &in) {
			return
		}
		email, err := policy.NormalizeEmail(in.Email)
		if err != nil || len(in.AuthHash) != 32 {
			httpx.Error(w, http.StatusBadRequest, "invalid_request")
			return
		}
		ctx := r.Context()
		u, err := users.FindByEmail(ctx, email)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		if u == nil {
			salt, _ := keys.Random(16)
			derive(in.AuthHash, salt, params)
			httpx.Error(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		t := now()
		if d := u.LockedFor(t); d > 0 {
			httpx.Locked(w, int((d+time.Minute-1)/time.Minute))
			return
		}
		ok, err := users.Attempt(ctx, u.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		if !ok {
			httpx.Locked(w, int(user.LockDuration/time.Minute))
			return
		}
		if subtle.ConstantTimeCompare(derive(in.AuthHash, u.AuthSalt, params), u.AuthHash) != 1 {
			httpx.Error(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		if err := users.ResetFailures(ctx, u.ID); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		if u.TOTPSecret != nil {
			if in.Code == "" {
				httpx.Error(w, http.StatusUnauthorized, "totp_required")
				return
			}
			counter, err := check.Check(ctx, u, u.TOTPSecret, in.Code, totp.IP(r))
			if err != nil {
				totp.WriteError(w, err)
				return
			}
			if ok, err := users.TOTPAccept(ctx, u.ID, counter); err != nil || !ok {
				totp.WriteError(w, cmp.Or(err, totp.ErrInvalid))
				return
			}
		}
		if err := sessions.PurgeExpired(ctx, t); err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		token, err := sessions.Create(ctx, u.ID, t)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		httpx.JSON(w, http.StatusOK, dto.Response{Token: token, UserID: u.ID, MasterBlob: u.MasterWrappedKey})
	}
}
