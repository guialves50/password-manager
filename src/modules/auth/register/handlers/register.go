package handlers

import (
	"context"
	"errors"
	"net/http"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/server/httpx"
)

type creator interface {
	Create(ctx context.Context, u *user.User) error
}

func New(repo creator, params keys.Params) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in dto.Request
		if !httpx.Decode(w, r, &in) {
			return
		}
		email, err := policy.NormalizeEmail(in.Email)
		if err != nil || in.KDF.Time == 0 || in.KDF.MemoryKiB == 0 || in.KDF.Threads == 0 ||
			len(in.MasterSalt) != 16 || len(in.RecoverySalt) != 16 ||
			len(in.AuthHash) != 32 || len(in.RecoveryAuthHash) != 32 ||
			len(in.MasterBlob) != 60 || len(in.RecoveryBlob) != 60 {
			httpx.Error(w, http.StatusBadRequest, "invalid_request")
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
		u := &user.User{
			Email:              email,
			KDFTime:            in.KDF.Time,
			KDFMemoryKiB:       in.KDF.MemoryKiB,
			KDFThreads:         in.KDF.Threads,
			MasterSalt:         in.MasterSalt,
			MasterWrappedKey:   in.MasterBlob,
			AuthSalt:           authSalt,
			AuthHash:           keys.Derive(in.AuthHash, authSalt, params),
			RecoverySalt:       in.RecoverySalt,
			RecoveryWrappedKey: in.RecoveryBlob,
			RecoveryAuthSalt:   recoveryAuthSalt,
			RecoveryAuthHash:   keys.Derive(in.RecoveryAuthHash, recoveryAuthSalt, params),
		}
		err = repo.Create(r.Context(), u)
		switch {
		case errors.Is(err, autherrors.ErrEmailTaken):
			httpx.Error(w, http.StatusConflict, "email_taken")
		case err != nil:
			httpx.Error(w, http.StatusInternalServerError, "internal")
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}
}
