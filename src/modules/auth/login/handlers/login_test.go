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
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	"github.com/guialves50/password-manager/src/modules/auth/totp"
	"github.com/guialves50/password-manager/src/modules/user"
)

var (
	testParams = keys.Params{Time: 1, MemoryKiB: 1024, Threads: 1}
	clock      = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	authHash   = bytes.Repeat([]byte{7}, 32)
)

type fakeUsers struct {
	u        *user.User
	findErr  error
	failErr  error
	raced    bool
	attempts []uint64
	resets   []uint64
	totpTry  int
	totpLock bool
	accepted []int64
	replayed bool
}

func (f *fakeUsers) TOTPAttempt(context.Context, uint64, time.Time) (bool, error) {
	f.totpTry++
	return !f.totpLock, nil
}

func (f *fakeUsers) TOTPAccept(_ context.Context, _ uint64, counter int64) (bool, error) {
	f.accepted = append(f.accepted, counter)
	return !f.replayed, nil
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

type fakeSessions struct {
	created   []uint64
	createdAt time.Time
	purgedAt  time.Time
	createErr error
}

func (f *fakeSessions) Create(_ context.Context, userID uint64, now time.Time) (string, error) {
	f.created = append(f.created, userID)
	f.createdAt = now
	return "tok", f.createErr
}

func (f *fakeSessions) PurgeExpired(_ context.Context, now time.Time) error {
	f.purgedAt = now
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
		ID: 42, Email: "alice@example.com", AuthSalt: salt,
		AuthHash: keys.Derive(authHash, salt, testParams), MasterWrappedKey: bytes.Repeat([]byte{9}, 60),
	}
}

func login(users *fakeUsers, sessions *fakeSessions, in dto.Request) (*httptest.ResponseRecorder, map[string]any) {
	b, _ := json.Marshal(in)
	rec := httptest.NewRecorder()
	now := func() time.Time { return clock }
	check := &totp.Checker{Users: users, Limiter: totp.NewLimiter(now), Key: totpKey, Now: now}
	NewLogin(users, sessions, check, testParams, now)(rec, httptest.NewRequest("POST", "/login", bytes.NewReader(b)))
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func TestLoginSuccess(t *testing.T) {
	n := countDerive(t)
	users, sessions := &fakeUsers{u: seed()}, &fakeSessions{}
	rec, _ := login(users, sessions, dto.Request{Email: " Alice@Example.com", AuthHash: authHash})
	var resp dto.Response
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || resp.Token != "tok" || resp.UserID != 42 || !bytes.Equal(resp.MasterBlob, users.u.MasterWrappedKey) {
		t.Fatalf("%d %+v", rec.Code, resp)
	}
	if *n != 1 || len(users.resets) != 1 || len(users.attempts) != 1 {
		t.Fatalf("derive=%d resets=%v attempts=%v", *n, users.resets, users.attempts)
	}
	if len(sessions.created) != 1 || sessions.created[0] != 42 || !sessions.createdAt.Equal(clock) || !sessions.purgedAt.Equal(clock) {
		t.Fatalf("sessions %+v", sessions)
	}
}

func TestLoginUnknownEmailRunsDummyDerive(t *testing.T) {
	n := countDerive(t)
	users, sessions := &fakeUsers{u: seed()}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "bob@example.com", AuthHash: authHash})
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_credentials" || *n != 1 {
		t.Fatalf("%d %v derive=%d", rec.Code, body, *n)
	}
	if len(sessions.created) != 0 || len(users.attempts) != 0 {
		t.Fatal("side effects on unknown email")
	}
}

func TestLoginWrongHashRecordsFailure(t *testing.T) {
	countDerive(t)
	users, sessions := &fakeUsers{u: seed()}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: bytes.Repeat([]byte{8}, 32)})
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_credentials" {
		t.Fatalf("%d %v", rec.Code, body)
	}
	if len(users.attempts) != 1 || users.attempts[0] != 42 || len(users.resets) != 0 || len(sessions.created) != 0 {
		t.Fatalf("attempts=%v resets=%v sessions=%v", users.attempts, users.resets, sessions.created)
	}
}

func TestLoginStoredHashNotAcceptedAsCredential(t *testing.T) {
	users := &fakeUsers{u: seed()}
	rec, _ := login(users, &fakeSessions{}, dto.Request{Email: "alice@example.com", AuthHash: users.u.AuthHash})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stored hash authenticated: %d", rec.Code)
	}
}

func TestLoginLockedSkipsDerive(t *testing.T) {
	n := countDerive(t)
	u := seed()
	until := clock.Add(14*time.Minute + time.Second)
	u.LockedUntil = &until
	users, sessions := &fakeUsers{u: u}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash})
	if rec.Code != http.StatusLocked || body["error"] != "locked" || body["minutes"] != float64(15) {
		t.Fatalf("%d %v", rec.Code, body)
	}
	if *n != 0 || len(users.attempts) != 0 || len(sessions.created) != 0 {
		t.Fatalf("derive=%d attempts=%v", *n, users.attempts)
	}
}

func TestLoginBadRequest(t *testing.T) {
	n := countDerive(t)
	for _, in := range []dto.Request{{Email: "nope", AuthHash: authHash}, {Email: "alice@example.com", AuthHash: authHash[:31]}} {
		if rec, body := login(&fakeUsers{u: seed()}, &fakeSessions{}, in); rec.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Errorf("%+v: %d %v", in, rec.Code, body)
		}
	}
	if *n != 0 {
		t.Fatal("derived on bad request")
	}
}

func TestLoginInternalErrors(t *testing.T) {
	cases := map[string]func() (*fakeUsers, *fakeSessions){
		"find": func() (*fakeUsers, *fakeSessions) { return &fakeUsers{findErr: errors.New("db")}, &fakeSessions{} },
		"failure": func() (*fakeUsers, *fakeSessions) {
			return &fakeUsers{u: seed(), failErr: errors.New("db")}, &fakeSessions{}
		},
		"session": func() (*fakeUsers, *fakeSessions) {
			return &fakeUsers{u: seed()}, &fakeSessions{createErr: errors.New("db")}
		},
	}
	for name, mk := range cases {
		users, sessions := mk()
		hash := authHash
		if name == "failure" {
			hash = bytes.Repeat([]byte{8}, 32)
		}
		if rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: hash}); rec.Code != http.StatusInternalServerError || body["error"] != "internal" {
			t.Errorf("%s: %d %v", name, rec.Code, body)
		}
	}
}

func TestLoginLockedConcurrentlySkipsDerive(t *testing.T) {
	n := countDerive(t)
	users, sessions := &fakeUsers{u: seed(), raced: true}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash})
	if rec.Code != http.StatusLocked || body["minutes"] != float64(15) || *n != 0 || len(users.resets) != 0 || len(sessions.created) != 0 {
		t.Fatalf("%d %v derive=%d", rec.Code, body, *n)
	}
}

var (
	totpKey = bytes.Repeat([]byte{5}, 32)
	totpRaw = []byte("12345678901234567890")
)

func seed2FA(t *testing.T) *user.User {
	u := seed()
	blob, err := totp.Seal(totpKey, u.ID, totpRaw)
	if err != nil {
		t.Fatal(err)
	}
	u.TOTPSecret = blob
	return u
}

func totpCode() string {
	return totp.Code(totpRaw, uint64(clock.Unix()/totp.Step), totp.Digits)
}

func TestLogin2FAWithoutCodeAsksForIt(t *testing.T) {
	users, sessions := &fakeUsers{u: seed2FA(t)}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash})
	if rec.Code != http.StatusUnauthorized || body["error"] != "totp_required" {
		t.Fatalf("%d %v", rec.Code, body)
	}
	if len(sessions.created) != 0 || users.totpTry != 0 {
		t.Fatalf("sessions=%v totp attempts=%d", sessions.created, users.totpTry)
	}
}

func TestLogin2FAValidCodeCreatesSession(t *testing.T) {
	users, sessions := &fakeUsers{u: seed2FA(t)}, &fakeSessions{}
	rec, _ := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash, Code: totpCode()})
	if rec.Code != http.StatusOK || len(sessions.created) != 1 {
		t.Fatalf("%d %v", rec.Code, sessions.created)
	}
	if len(users.accepted) != 1 || users.accepted[0] != clock.Unix()/totp.Step {
		t.Fatalf("accepted %v", users.accepted)
	}
}

func TestLogin2FAWrongCode(t *testing.T) {
	users, sessions := &fakeUsers{u: seed2FA(t)}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash, Code: "000000"})
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_totp" || len(sessions.created) != 0 || users.totpTry != 1 {
		t.Fatalf("%d %v", rec.Code, body)
	}
}

func TestLogin2FAWrongPasswordSkipsCode(t *testing.T) {
	users, sessions := &fakeUsers{u: seed2FA(t)}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: bytes.Repeat([]byte{8}, 32), Code: totpCode()})
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_credentials" || users.totpTry != 0 {
		t.Fatalf("%d %v try=%d", rec.Code, body, users.totpTry)
	}
}

func TestLogin2FALockedEvenWithValidCode(t *testing.T) {
	users, sessions := &fakeUsers{u: seed2FA(t), totpLock: true}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash, Code: totpCode()})
	if rec.Code != http.StatusLocked || body["minutes"] != float64(10) || len(sessions.created) != 0 {
		t.Fatalf("%d %v", rec.Code, body)
	}
}

func TestLogin2FAReplayRejected(t *testing.T) {
	users, sessions := &fakeUsers{u: seed2FA(t), replayed: true}, &fakeSessions{}
	rec, body := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash, Code: totpCode()})
	if rec.Code != http.StatusUnauthorized || body["error"] != "invalid_totp" || len(sessions.created) != 0 {
		t.Fatalf("%d %v", rec.Code, body)
	}
}

func TestLoginWithout2FAIgnoresCode(t *testing.T) {
	users, sessions := &fakeUsers{u: seed()}, &fakeSessions{}
	rec, _ := login(users, sessions, dto.Request{Email: "alice@example.com", AuthHash: authHash, Code: "000000"})
	if rec.Code != http.StatusOK || users.totpTry != 0 {
		t.Fatalf("%d try=%d", rec.Code, users.totpTry)
	}
}
