package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/server/httpx"
)

type rotator interface {
	RotateAuth(ctx context.Context, id uint64, verifiedRecoveryAuthHash []byte, next *user.User) error
}

func NewFinish(users userStore, repo rotator, params keys.Params, now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in dto.FinishRequest
		if !httpx.Decode(w, r, &in) {
			return
		}
		email, err := policy.NormalizeEmail(in.Email)
		if err != nil || len(in.RecoveryAuthHash) != 32 || len(in.AuthHash) != 32 || len(in.NewRecoveryAuthHash) != 32 ||
			len(in.MasterSalt) != 16 || len(in.RecoverySalt) != 16 ||
			len(in.MasterBlob) != 60 || len(in.RecoveryBlob) != 60 {
			httpx.Error(w, http.StatusBadRequest, "invalid_request")
			return
		}
		u := verify(w, r, users, email, in.RecoveryAuthHash, params, now())
		if u == nil {
			return
		}
		authSalt, err := keys.Random(16)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		recoveryAuthSalt, err := keys.Random(16)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		err = repo.RotateAuth(r.Context(), u.ID, u.RecoveryAuthHash, &user.User{
			MasterSalt:         in.MasterSalt,
			MasterWrappedKey:   in.MasterBlob,
			AuthSalt:           authSalt,
			AuthHash:           derive(in.AuthHash, authSalt, params),
			RecoverySalt:       in.RecoverySalt,
			RecoveryWrappedKey: in.RecoveryBlob,
			RecoveryAuthSalt:   recoveryAuthSalt,
			RecoveryAuthHash:   derive(in.NewRecoveryAuthHash, recoveryAuthSalt, params),
		})
		switch {
		case errors.Is(err, autherrors.ErrInvalidRecovery):
			httpx.Error(w, http.StatusUnauthorized, "invalid_recovery")
		case err != nil:
			httpx.Error(w, http.StatusInternalServerError, "internal")
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
