package handlers

import (
	"context"
	"net/http"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/totp"
	"github.com/guialves50/password-manager/src/modules/auth/twofactor/dto"
	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/server/httpx"
)

type store interface {
	FindByID(ctx context.Context, id uint64) (*user.User, error)
	SetTOTPPending(ctx context.Context, id uint64, blob []byte) (bool, error)
	ActivateTOTP(ctx context.Context, id uint64, counter int64) (bool, error)
}

func load(w http.ResponseWriter, r *http.Request, users store) *user.User {
	u, err := users.FindByID(r.Context(), session.UserID(r.Context()))
	if err != nil || u == nil {
		httpx.Error(w, http.StatusInternalServerError, "internal")
		return nil
	}
	if u.TOTPSecret != nil {
		httpx.Error(w, http.StatusConflict, "totp_enabled")
		return nil
	}
	return u
}

func NewSetup(users store, key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := load(w, r, users)
		if u == nil {
			return
		}
		secret, err := keys.Random(20)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		defer clear(secret)
		blob, err := totp.Seal(key, u.ID, secret)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		ok, err := users.SetTOTPPending(r.Context(), u.ID, blob)
		switch {
		case err != nil:
			httpx.Error(w, http.StatusInternalServerError, "internal")
		case !ok:
			httpx.Error(w, http.StatusConflict, "totp_enabled")
		default:
			httpx.JSON(w, http.StatusOK, dto.SetupResponse{Secret: totp.Base32(secret), URI: totp.URI(u.Email, secret)})
		}
	}
}

func NewConfirm(users store, check *totp.Checker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in dto.ConfirmRequest
		if !httpx.Decode(w, r, &in) {
			return
		}
		u := load(w, r, users)
		if u == nil {
			return
		}
		if u.TOTPPending == nil {
			httpx.Error(w, http.StatusConflict, "no_pending")
			return
		}
		counter, err := check.Check(r.Context(), u, u.TOTPPending, in.Code, totp.IP(r))
		if err != nil {
			totp.WriteError(w, err)
			return
		}
		ok, err := users.ActivateTOTP(r.Context(), u.ID, counter)
		switch {
		case err != nil:
			httpx.Error(w, http.StatusInternalServerError, "internal")
		case !ok:
			httpx.Error(w, http.StatusConflict, "no_pending")
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
