package handlers

import (
	"net/http"
	"time"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	"github.com/guialves50/password-manager/src/server/httpx"
)

func NewStart(users userStore, params keys.Params, now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in dto.StartRequest
		if !httpx.Decode(w, r, &in) {
			return
		}
		email, err := policy.NormalizeEmail(in.Email)
		if err != nil || len(in.RecoveryAuthHash) != 32 {
			httpx.Error(w, http.StatusBadRequest, "invalid_request")
			return
		}
		u := verify(w, r, users, email, in.RecoveryAuthHash, params, now())
		if u == nil {
			return
		}
		httpx.JSON(w, http.StatusOK, dto.StartResponse{RecoveryBlob: u.RecoveryWrappedKey})
	}
}
