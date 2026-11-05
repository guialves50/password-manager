package server

import (
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	login "github.com/guialves50/password-manager/src/modules/auth/login/handlers"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/handlers"
	recovery "github.com/guialves50/password-manager/src/modules/auth/recover/handlers"
	recoverrepo "github.com/guialves50/password-manager/src/modules/auth/recover/repository"
	register "github.com/guialves50/password-manager/src/modules/auth/register/handlers"
	registerrepo "github.com/guialves50/password-manager/src/modules/auth/register/repository"
	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/user"
	items "github.com/guialves50/password-manager/src/modules/vault/items/handlers"
	itemsrepo "github.com/guialves50/password-manager/src/modules/vault/items/repository"
	"github.com/guialves50/password-manager/src/server/httpx"
)

const MaxDerivations = 4

type Config struct {
	Secret     []byte
	AuthParams keys.Params
	Now        func() time.Time
}

func New(db *gorm.DB, cfg Config) http.Handler {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	users := user.NewRepository(db)
	sessions := session.NewRepository(db)
	vault := itemsrepo.New(db)
	auth := session.Require(sessions, now)
	kdf := httpx.Gate(MaxDerivations)

	mux := http.NewServeMux()
	mux.Handle("POST /prelogin", prelogin.New(users, cfg.Secret))
	mux.Handle("POST /register", kdf(register.New(registerrepo.New(db), cfg.AuthParams)))
	mux.Handle("POST /login", kdf(login.NewLogin(users, sessions, cfg.AuthParams, now)))
	mux.Handle("POST /logout", auth(login.NewLogout(sessions)))
	mux.Handle("POST /recover/start", kdf(recovery.NewStart(users, cfg.AuthParams, now)))
	mux.Handle("POST /recover/finish", kdf(recovery.NewFinish(users, recoverrepo.New(db), cfg.AuthParams, now)))
	mux.Handle("GET /items", auth(items.NewList(vault)))
	mux.Handle("POST /items", auth(items.NewCreate(vault)))
	mux.Handle("DELETE /items/{id}", auth(items.NewDelete(vault)))
	return httpx.Limit(mux)
}
