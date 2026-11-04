package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

var testParams = keys.Params{Time: 1, MemoryKiB: 1024, Threads: 1}

type fakeRepo struct {
	got *user.User
	err error
}

func (f *fakeRepo) Create(_ context.Context, u *user.User) error {
	f.got = u
	return f.err
}

func fill(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func validRequest() dto.Request {
	return dto.Request{
		Email: " Alice@Example.com ", KDF: prelogin.KDF{Time: 3, MemoryKiB: 65536, Threads: 4},
		MasterSalt: fill(16, 1), MasterBlob: fill(60, 2), AuthHash: fill(32, 3),
		RecoverySalt: fill(16, 4), RecoveryBlob: fill(60, 5), RecoveryAuthHash: fill(32, 6),
	}
}

func send(repo *fakeRepo, body any) (*httptest.ResponseRecorder, string) {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	New(repo, testParams)(rec, httptest.NewRequest("POST", "/register", bytes.NewReader(b)))
	var e struct{ Error string }
	json.Unmarshal(rec.Body.Bytes(), &e)
	return rec, e.Error
}

func TestRegisterStoresOnlyServerHashes(t *testing.T) {
	repo := &fakeRepo{}
	in := validRequest()
	rec, _ := send(repo, in)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code %d %q", rec.Code, rec.Body)
	}
	u := repo.got
	if u.Email != "alice@example.com" || u.KDFTime != 3 || u.KDFMemoryKiB != 65536 || u.KDFThreads != 4 {
		t.Fatalf("user %+v", u)
	}
	if !bytes.Equal(u.MasterSalt, in.MasterSalt) || !bytes.Equal(u.MasterWrappedKey, in.MasterBlob) ||
		!bytes.Equal(u.RecoverySalt, in.RecoverySalt) || !bytes.Equal(u.RecoveryWrappedKey, in.RecoveryBlob) {
		t.Fatal("salts/blobs not stored as sent")
	}
	if len(u.AuthSalt) != 16 || len(u.RecoveryAuthSalt) != 16 || bytes.Equal(u.AuthSalt, u.RecoveryAuthSalt) {
		t.Fatalf("auth salts %x %x", u.AuthSalt, u.RecoveryAuthSalt)
	}
	if bytes.Equal(u.AuthHash, in.AuthHash) || !bytes.Equal(u.AuthHash, keys.Derive(in.AuthHash, u.AuthSalt, testParams)) {
		t.Fatal("auth hash not argon2id(auth_hash, auth_salt)")
	}
	if bytes.Equal(u.RecoveryAuthHash, in.RecoveryAuthHash) || !bytes.Equal(u.RecoveryAuthHash, keys.Derive(in.RecoveryAuthHash, u.RecoveryAuthSalt, testParams)) {
		t.Fatal("recovery auth hash not argon2id(recovery_auth_hash, recovery_auth_salt)")
	}
	for _, f := range [][]byte{u.MasterSalt, u.MasterWrappedKey, u.AuthSalt, u.AuthHash, u.RecoverySalt, u.RecoveryWrappedKey, u.RecoveryAuthSalt, u.RecoveryAuthHash} {
		if bytes.Contains(f, in.AuthHash) || bytes.Contains(f, in.RecoveryAuthHash) {
			t.Fatal("client hash stored in clear")
		}
	}
}

func TestRegisterValidation(t *testing.T) {
	cases := map[string]func(*dto.Request){
		"email":         func(r *dto.Request) { r.Email = "nope" },
		"kdf time":      func(r *dto.Request) { r.KDF.Time = 0 },
		"kdf memory":    func(r *dto.Request) { r.KDF.MemoryKiB = 0 },
		"kdf threads":   func(r *dto.Request) { r.KDF.Threads = 0 },
		"master salt":   func(r *dto.Request) { r.MasterSalt = fill(15, 1) },
		"recovery salt": func(r *dto.Request) { r.RecoverySalt = fill(17, 1) },
		"auth hash":     func(r *dto.Request) { r.AuthHash = nil },
		"recovery hash": func(r *dto.Request) { r.RecoveryAuthHash = fill(31, 1) },
		"master blob":   func(r *dto.Request) { r.MasterBlob = fill(59, 1) },
		"recovery blob": func(r *dto.Request) { r.RecoveryBlob = fill(61, 1) },
	}
	for name, mutate := range cases {
		repo := &fakeRepo{}
		in := validRequest()
		mutate(&in)
		rec, code := send(repo, in)
		if rec.Code != http.StatusBadRequest || code != "invalid_request" || repo.got != nil {
			t.Errorf("%s: %d %q created=%v", name, rec.Code, code, repo.got != nil)
		}
	}
	rec := httptest.NewRecorder()
	New(&fakeRepo{}, testParams)(rec, httptest.NewRequest("POST", "/register", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", rec.Code)
	}
}

func TestRegisterRepoErrors(t *testing.T) {
	if rec, code := send(&fakeRepo{err: autherrors.ErrEmailTaken}, validRequest()); rec.Code != http.StatusConflict || code != "email_taken" {
		t.Fatalf("duplicate: %d %q", rec.Code, code)
	}
	if rec, code := send(&fakeRepo{err: errors.New("db")}, validRequest()); rec.Code != http.StatusInternalServerError || code != "internal" {
		t.Fatalf("db error: %d %q", rec.Code, code)
	}
}
