package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

var (
	testParams   = keys.Params{Time: 1, MemoryKiB: 1024, Threads: 1}
	clock        = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	recoveryHash = bytes.Repeat([]byte{7}, 32)
	wrongHash    = bytes.Repeat([]byte{8}, 32)
)

type fakeUsers struct {
	u        *user.User
	findErr  error
	failErr  error
	raced    bool
	attempts []uint64
	resets   []uint64
}

func (f *fakeUsers) FindByEmail(_ context.Context, email string) (*user.User, error) {
	if f.findErr != nil || f.u == nil || f.u.Email != email {
		return nil, f.findErr
	}
	return f.u, nil
}

func (f *fakeUsers) Attempt(_ context.Context, id uint64) (bool, error) {
	f.attempts = append(f.attempts, id)
	return !f.raced, f.failErr
}

func (f *fakeUsers) ResetFailures(_ context.Context, id uint64) error {
	f.resets = append(f.resets, id)
	return nil
}

func countDerive(t *testing.T) *int {
	t.Helper()
	n := 0
	orig := derive
	derive = func(secret, salt []byte, p keys.Params) []byte {
		n++
		if p != testParams {
			t.Errorf("derive params %+v", p)
		}
		return orig(secret, salt, p)
	}
	t.Cleanup(func() { derive = orig })
	return &n
}

func seed() *user.User {
	salt := bytes.Repeat([]byte{1}, 16)
	return &user.User{
		ID: 42, Email: "alice@example.com", RecoveryAuthSalt: salt,
		RecoveryAuthHash: keys.Derive(recoveryHash, salt, testParams), RecoveryWrappedKey: bytes.Repeat([]byte{9}, 60),
	}
}

func locked(u *user.User) *user.User {
	until := clock.Add(3*time.Minute + time.Second)
	u.LockedUntil = &until
	return u
}

func call(h http.HandlerFunc, path string, in any) (*httptest.ResponseRecorder, map[string]any) {
	b, _ := json.Marshal(in)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", path, bytes.NewReader(b)))
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func start(users *fakeUsers, in dto.StartRequest) (*httptest.ResponseRecorder, map[string]any) {
	return call(NewStart(users, testParams, func() time.Time { return clock }), "/recover/start", in)
}

func TestStartSuccess(t *testing.T) {
	n := countDerive(t)
	users := &fakeUsers{u: seed()}
	rec, _ := start(users, dto.StartRequest{Email: "Alice@example.com ", RecoveryAuthHash: recoveryHash})
	var resp dto.StartResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !bytes.Equal(resp.RecoveryBlob, users.u.RecoveryWrappedKey) || *n != 1 || len(users.attempts) != 1 || len(users.resets) != 1 {
		t.Fatalf("%d %+v derive=%d attempts=%v resets=%v", rec.Code, resp, *n, users.attempts, users.resets)
	}
}

func TestStartUnknownEmailRunsDummyDerive(t *testing.T) {
	n := countDerive(t)
	users := &fakeUsers{u: seed()}
	rec, body := start(users, dto.StartRequest{Email: "bob@example.com", RecoveryAuthHash: recoveryHash})
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_recovery" || *n != 1 || len(users.attempts) != 0 {
		t.Fatalf("%d %v derive=%d attempts=%v", rec.Code, body, *n, users.attempts)
	}
}

func TestStartWrongHashRecordsFailure(t *testing.T) {
	users := &fakeUsers{u: seed()}
	rec, body := start(users, dto.StartRequest{Email: "alice@example.com", RecoveryAuthHash: wrongHash})
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_recovery" || len(users.attempts) != 1 || users.attempts[0] != 42 || len(users.resets) != 0 {
		t.Fatalf("%d %v attempts=%v", rec.Code, body, users.attempts)
	}
	if _, leaked := body["recovery_blob"]; leaked {
		t.Fatal("blob returned on failure")
	}
}

func TestStartLockedSkipsDerive(t *testing.T) {
	n := countDerive(t)
	users := &fakeUsers{u: locked(seed())}
	rec, body := start(users, dto.StartRequest{Email: "alice@example.com", RecoveryAuthHash: recoveryHash})
	if rec.Code != http.StatusLocked || body["error"] != "locked" || body["minutes"] != float64(4) || *n != 0 || len(users.attempts) != 0 {
		t.Fatalf("%d %v derive=%d", rec.Code, body, *n)
	}
}

func TestStartErrors(t *testing.T) {
	for _, in := range []dto.StartRequest{{Email: "nope", RecoveryAuthHash: recoveryHash}, {Email: "alice@example.com", RecoveryAuthHash: recoveryHash[:16]}} {
		if rec, body := start(&fakeUsers{u: seed()}, in); rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Errorf("%+v: %d %v", in, rec.Code, body)
		}
	}
	if rec, body := start(&fakeUsers{findErr: errors.New("db")}, dto.StartRequest{Email: "alice@example.com", RecoveryAuthHash: recoveryHash}); rec.Code != http.StatusInternalServerError || body["error"] != "internal" {
		t.Fatalf("find: %d %v", rec.Code, body)
	}
	if rec, body := start(&fakeUsers{u: seed(), failErr: errors.New("db")}, dto.StartRequest{Email: "alice@example.com", RecoveryAuthHash: wrongHash}); rec.Code != http.StatusInternalServerError || body["error"] != "internal" {
		t.Fatalf("record: %d %v", rec.Code, body)
	}
}

func TestStartLockedConcurrentlySkipsDerive(t *testing.T) {
	n := countDerive(t)
	users := &fakeUsers{u: seed(), raced: true}
	rec, body := start(users, dto.StartRequest{Email: "alice@example.com", RecoveryAuthHash: recoveryHash})
	if rec.Code != http.StatusLocked || body["minutes"] != float64(15) || *n != 0 || len(users.resets) != 0 {
		t.Fatalf("%d %v derive=%d", rec.Code, body, *n)
	}
	if _, leaked := body["recovery_blob"]; leaked {
		t.Fatal("blob returned while locked")
	}
}
