package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/modules/auth/totp"
	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/user"
)

var (
	key   = bytes.Repeat([]byte{9}, 32)
	clock = time.Unix(1111111109, 0)
	raw   = []byte("12345678901234567890")
)

type toucher struct{}

func (toucher) Touch(context.Context, string, time.Time) (uint64, bool, error) { return 7, true, nil }

type fakeStore struct {
	u         *user.User
	pending   []byte
	activated []int64
	attemptOK bool
}

func (f *fakeStore) FindByID(_ context.Context, id uint64) (*user.User, error) {
	if f.u == nil || f.u.ID != id {
		return nil, nil
	}
	c := *f.u
	return &c, nil
}

func (f *fakeStore) SetTOTPPending(_ context.Context, _ uint64, blob []byte) (bool, error) {
	f.pending = blob
	return true, nil
}

func (f *fakeStore) ActivateTOTP(_ context.Context, _ uint64, counter int64) (bool, error) {
	f.activated = append(f.activated, counter)
	return true, nil
}

func (f *fakeStore) TOTPAttempt(context.Context, uint64, time.Time) (bool, error) {
	return f.attemptOK, nil
}

func serve(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/2fa", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	session.Require(toucher{}, time.Now)(h).ServeHTTP(rec, req)
	return rec
}

func checker(f *fakeStore) *totp.Checker {
	now := func() time.Time { return clock }
	return &totp.Checker{Users: f, Limiter: totp.NewLimiter(now), Key: key, Now: now}
}

func errorCode(rec *httptest.ResponseRecorder) string {
	var e struct{ Error string }
	json.Unmarshal(rec.Body.Bytes(), &e)
	return e.Error
}

func TestSetupStoresSealedPendingAndReturnsURI(t *testing.T) {
	f := &fakeStore{u: &user.User{ID: 7, Email: "ana@x.com"}}
	rec := serve(NewSetup(f, key), "")
	var out struct{ Secret, URI string }
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Secret) != 32 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix(out.URI, "otpauth://totp/Guardian:ana@x.com?") || !strings.Contains(out.URI, "secret="+out.Secret) || !strings.Contains(out.URI, "issuer=Guardian") {
		t.Fatalf("uri %s", out.URI)
	}
	secret, err := totp.Open(key, 7, f.pending)
	if err != nil || len(secret) != 20 || totp.Base32(secret) != out.Secret {
		t.Fatalf("pending: %v", err)
	}
}

func TestSetupRefusedWhenActive(t *testing.T) {
	f := &fakeStore{u: &user.User{ID: 7, TOTPSecret: []byte("x")}}
	rec := serve(NewSetup(f, key), "")
	if rec.Code != 409 || errorCode(rec) != "totp_enabled" || f.pending != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func pendingUser(t *testing.T) *user.User {
	blob, err := totp.Seal(key, 7, raw)
	if err != nil {
		t.Fatal(err)
	}
	return &user.User{ID: 7, TOTPPending: blob}
}

func code(step int64) string {
	return `{"code":"` + totp.Code(raw, uint64(clock.Unix()/totp.Step+step), totp.Digits) + `"}`
}

func TestConfirmActivates(t *testing.T) {
	f := &fakeStore{u: pendingUser(t), attemptOK: true}
	rec := serve(NewConfirm(f, checker(f)), code(0))
	if rec.Code != 204 || len(f.activated) != 1 || f.activated[0] != clock.Unix()/totp.Step {
		t.Fatalf("%d %s %v", rec.Code, rec.Body, f.activated)
	}
}

func TestConfirmErrors(t *testing.T) {
	cases := []struct {
		name   string
		u      *user.User
		ok     bool
		body   string
		status int
		code   string
	}{
		{"no pending", &user.User{ID: 7}, true, code(0), 409, "no_pending"},
		{"already active", &user.User{ID: 7, TOTPSecret: []byte("x")}, true, code(0), 409, "totp_enabled"},
		{"wrong code", pendingUser(t), true, `{"code":"000000"}`, 401, "invalid_totp"},
		{"malformed code", pendingUser(t), true, `{"code":"12ab"}`, 401, "invalid_totp"},
		{"account locked", pendingUser(t), false, code(0), 423, "locked"},
	}
	for _, c := range cases {
		f := &fakeStore{u: c.u, attemptOK: c.ok}
		rec := serve(NewConfirm(f, checker(f)), c.body)
		if rec.Code != c.status || errorCode(rec) != c.code || len(f.activated) != 0 {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
	}
}

func TestConfirmIPLockedAfterThreeWrongCodes(t *testing.T) {
	f := &fakeStore{u: pendingUser(t), attemptOK: true}
	h := NewConfirm(f, checker(f))
	for range 3 {
		serve(h, `{"code":"000000"}`)
	}
	rec := serve(h, code(0))
	var e struct{ Minutes int }
	json.Unmarshal(rec.Body.Bytes(), &e)
	if rec.Code != 423 || e.Minutes != 10 || len(f.activated) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// Edge case: a malformed code is a wrong guess and counts toward the limit.
func TestConfirmMalformedCodesCountAsFailures(t *testing.T) {
	f := &fakeStore{u: pendingUser(t), attemptOK: true}
	h := NewConfirm(f, checker(f))
	for range 3 {
		serve(h, `{"code":"12ab"}`)
	}
	if rec := serve(h, code(0)); rec.Code != 423 || errorCode(rec) != "locked" || len(f.activated) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
