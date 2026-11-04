package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/server/httpx"
)

type finder interface {
	FindByEmail(ctx context.Context, email string) (*user.User, error)
}

func New(users finder, secret []byte) http.HandlerFunc {
	fakeSalt := func(label, email string) []byte {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(label + "|" + email))
		return m.Sum(nil)[:16]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in dto.Request
		if !httpx.Decode(w, r, &in) {
			return
		}
		email, err := policy.NormalizeEmail(in.Email)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_request")
			return
		}
		u, err := users.FindByEmail(r.Context(), email)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "internal")
			return
		}
		if u == nil {
			p := keys.DefaultParams
			httpx.JSON(w, http.StatusOK, dto.Response{
				KDF:          dto.KDF{Time: p.Time, MemoryKiB: p.MemoryKiB, Threads: p.Threads},
				MasterSalt:   fakeSalt("master", email),
				RecoverySalt: fakeSalt("recovery", email),
			})
			return
		}
		httpx.JSON(w, http.StatusOK, dto.Response{
			KDF:          dto.KDF{Time: u.KDFTime, MemoryKiB: u.KDFMemoryKiB, Threads: u.KDFThreads},
			MasterSalt:   u.MasterSalt,
			RecoverySalt: u.RecoverySalt,
		})
	}
}
