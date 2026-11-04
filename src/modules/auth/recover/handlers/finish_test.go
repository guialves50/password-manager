package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

type fakeRotator struct {
	calls    int
	id       uint64
	verified []byte
	next     *user.User
	err      error
}

func (f *fakeRotator) RotateAuth(_ context.Context, id uint64, verified []byte, next *user.User) error {
	f.calls++
	f.id, f.verified, f.next = id, verified, next
	return f.err
}

func fill(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func finishRequest(hash []byte) dto.FinishRequest {
	return dto.FinishRequest{
		Email: "alice@example.com", RecoveryAuthHash: hash,
		MasterSalt: fill(16, 1), MasterBlob: fill(60, 2), AuthHash: fill(32, 3),
		RecoverySalt: fill(16, 4), RecoveryBlob: fill(60, 5), NewRecoveryAuthHash: fill(32, 6),
	}
}

func finish(users *fakeUsers, rot *fakeRotator, in dto.FinishRequest) (*httptest.ResponseRecorder, map[string]any) {
	return call(NewFinish(users, rot, testParams, func() time.Time { return clock }), "/recover/finish", in)
}

func TestFinishSuccess(t *testing.T) {
	users, rot := &fakeUsers{u: seed()}, &fakeRotator{}
	stored := users.u.RecoveryAuthHash
	in := finishRequest(recoveryHash)
	rec, _ := finish(users, rot, in)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	if rot.calls != 1 || rot.id != 42 || !bytes.Equal(rot.verified, stored) {
		t.Fatalf("rotate calls=%d id=%d verified=%x", rot.calls, rot.id, rot.verified)
	}
	n := rot.next
	if !bytes.Equal(n.MasterSalt, in.MasterSalt) || !bytes.Equal(n.MasterWrappedKey, in.MasterBlob) ||
		!bytes.Equal(n.RecoverySalt, in.RecoverySalt) || !bytes.Equal(n.RecoveryWrappedKey, in.RecoveryBlob) {
		t.Fatal("salts/blobs not passed through")
	}
	if len(n.AuthSalt) != 16 || len(n.RecoveryAuthSalt) != 16 || bytes.Equal(n.AuthSalt, n.RecoveryAuthSalt) {
		t.Fatalf("auth salts %x %x", n.AuthSalt, n.RecoveryAuthSalt)
	}
	if bytes.Equal(n.AuthHash, in.AuthHash) || !bytes.Equal(n.AuthHash, keys.Derive(in.AuthHash, n.AuthSalt, testParams)) {
		t.Fatal("auth hash not passed through argon2id")
	}
	if bytes.Equal(n.RecoveryAuthHash, in.NewRecoveryAuthHash) || !bytes.Equal(n.RecoveryAuthHash, keys.Derive(in.NewRecoveryAuthHash, n.RecoveryAuthSalt, testParams)) {
		t.Fatal("new recovery auth hash not passed through argon2id")
	}
	if len(users.failures) != 0 {
		t.Fatalf("failures %v", users.failures)
	}
}

func TestFinishWrongHashCountsFailure(t *testing.T) {
	users, rot := &fakeUsers{u: seed()}, &fakeRotator{}
	rec, body := finish(users, rot, finishRequest(wrongHash))
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_recovery" || len(users.failures) != 1 || rot.calls != 0 {
		t.Fatalf("%d %v failures=%v rotate=%d", rec.Code, body, users.failures, rot.calls)
	}
}

func TestFinishUnknownEmailRunsDummyDerive(t *testing.T) {
	n := countDerive(t)
	users, rot := &fakeUsers{u: seed()}, &fakeRotator{}
	in := finishRequest(recoveryHash)
	in.Email = "bob@example.com"
	rec, body := finish(users, rot, in)
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_recovery" || *n != 1 || rot.calls != 0 {
		t.Fatalf("%d %v derive=%d rotate=%d", rec.Code, body, *n, rot.calls)
	}
}

func TestFinishLockedSkipsDerive(t *testing.T) {
	n := countDerive(t)
	users, rot := &fakeUsers{u: locked(seed())}, &fakeRotator{}
	rec, body := finish(users, rot, finishRequest(recoveryHash))
	if rec.Code != http.StatusLocked || body["error"] != "locked" || body["minutes"] != float64(4) || *n != 0 || rot.calls != 0 {
		t.Fatalf("%d %v derive=%d rotate=%d", rec.Code, body, *n, rot.calls)
	}
}

func TestFinishRaceLost(t *testing.T) {
	users, rot := &fakeUsers{u: seed()}, &fakeRotator{err: autherrors.ErrInvalidRecovery}
	rec, body := finish(users, rot, finishRequest(recoveryHash))
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_recovery" {
		t.Fatalf("%d %v", rec.Code, body)
	}
	rec, body = finish(users, &fakeRotator{err: errors.New("db")}, finishRequest(recoveryHash))
	if rec.Code != http.StatusInternalServerError || body["error"] != "internal" {
		t.Fatalf("db error: %d %v", rec.Code, body)
	}
}

func TestFinishValidation(t *testing.T) {
	cases := map[string]func(*dto.FinishRequest){
		"email":             func(r *dto.FinishRequest) { r.Email = "nope" },
		"recovery hash":     func(r *dto.FinishRequest) { r.RecoveryAuthHash = fill(31, 7) },
		"master salt":       func(r *dto.FinishRequest) { r.MasterSalt = fill(15, 1) },
		"master blob":       func(r *dto.FinishRequest) { r.MasterBlob = fill(61, 1) },
		"auth hash":         func(r *dto.FinishRequest) { r.AuthHash = nil },
		"recovery salt":     func(r *dto.FinishRequest) { r.RecoverySalt = fill(17, 1) },
		"recovery blob":     func(r *dto.FinishRequest) { r.RecoveryBlob = fill(59, 1) },
		"new recovery hash": func(r *dto.FinishRequest) { r.NewRecoveryAuthHash = fill(33, 1) },
	}
	for name, mutate := range cases {
		users, rot := &fakeUsers{u: seed()}, &fakeRotator{}
		in := finishRequest(recoveryHash)
		mutate(&in)
		rec, body := finish(users, rot, in)
		if rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" || rot.calls != 0 || len(users.failures) != 0 {
			t.Errorf("%s: %d %v rotate=%d", name, rec.Code, body, rot.calls)
		}
	}
}
