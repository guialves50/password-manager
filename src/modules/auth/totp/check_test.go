package totp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/user"
)

type fakeAttempt struct {
	ok    bool
	err   error
	calls int
}

func (f *fakeAttempt) TOTPAttempt(context.Context, uint64, time.Time) (bool, error) {
	f.calls++
	return f.ok, f.err
}

var (
	key   = bytes.Repeat([]byte{9}, 32)
	clock = time.Unix(1111111109, 0)
)

func newChecker(a *fakeAttempt) *Checker {
	now := func() time.Time { return clock }
	return &Checker{Users: a, Limiter: NewLimiter(now), Key: key, Now: now}
}

func sealed(t *testing.T, id uint64) []byte {
	t.Helper()
	b, err := Seal(key, id, rfcSecret)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func current() string { return Code(rfcSecret, uint64(clock.Unix()/Step), Digits) }

func TestCheckAcceptsValidCode(t *testing.T) {
	a := &fakeAttempt{ok: true}
	got, err := newChecker(a).Check(context.Background(), &user.User{ID: 1}, sealed(t, 1), current(), "ip")
	if err != nil || got != clock.Unix()/Step || a.calls != 1 {
		t.Fatalf("%d %v calls=%d", got, err, a.calls)
	}
}

func TestCheckWrongCodeCountsForIP(t *testing.T) {
	c := newChecker(&fakeAttempt{ok: true})
	u := &user.User{ID: 1}
	for range 3 {
		if _, err := c.Check(context.Background(), u, sealed(t, 1), "000000", "ip"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("wrong code: %v", err)
		}
	}
	var l *autherrors.LockedError
	if _, err := c.Check(context.Background(), u, sealed(t, 1), current(), "ip"); !errors.As(err, &l) || l.Minutes != 10 {
		t.Fatalf("4th from locked ip: %v", err)
	}
	if _, err := c.Check(context.Background(), &user.User{ID: 2}, sealed(t, 2), current(), "ip"); !errors.As(err, &l) {
		t.Fatalf("other account from locked ip: %v", err)
	}
	if _, err := c.Check(context.Background(), u, sealed(t, 1), current(), "other"); err != nil {
		t.Fatalf("other ip: %v", err)
	}
}

func TestCheckAccountLocked(t *testing.T) {
	until := clock.Add(4*time.Minute + time.Second)
	a := &fakeAttempt{ok: true}
	var l *autherrors.LockedError
	_, err := newChecker(a).Check(context.Background(), &user.User{ID: 1, TOTPLockedUntil: &until}, sealed(t, 1), current(), "ip")
	if !errors.As(err, &l) || l.Minutes != 5 || a.calls != 0 {
		t.Fatalf("locked row: %v calls=%d", err, a.calls)
	}
	_, err = newChecker(&fakeAttempt{ok: false}).Check(context.Background(), &user.User{ID: 1}, sealed(t, 1), current(), "ip")
	if !errors.As(err, &l) || l.Minutes != 10 {
		t.Fatalf("attempt refused: %v", err)
	}
}

func TestCheckReplayRejected(t *testing.T) {
	u := &user.User{ID: 1, TOTPLastCounter: clock.Unix() / Step}
	if _, err := newChecker(&fakeAttempt{ok: true}).Check(context.Background(), u, sealed(t, 1), current(), "ip"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replay: %v", err)
	}
}

// Edge case: a secret this server can't open is not the user's fault, so it
// is reported as unreadable and counts against neither the account nor the IP.
func TestCheckUndecryptableSecret(t *testing.T) {
	a := &fakeAttempt{ok: true}
	c := newChecker(a)
	for range 3 {
		if _, err := c.Check(context.Background(), &user.User{ID: 1}, sealed(t, 2), current(), "ip"); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("got %v", err)
		}
	}
	if a.calls != 0 || c.Limiter.LockedFor("ip") != 0 {
		t.Fatalf("counted: account attempts %d, ip locked %v", a.calls, c.Limiter.LockedFor("ip"))
	}
	if _, err := newChecker(a).Check(context.Background(), &user.User{ID: 1}, sealed(t, 1), current(), "ip"); err != nil {
		t.Fatalf("readable secret after: %v", err)
	}
}

func TestWriteError(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		body   string
	}{
		{&autherrors.LockedError{Minutes: 3}, 423, `{"error":"locked","minutes":3}`},
		{ErrInvalid, 401, `{"error":"invalid_totp"}`},
		{ErrUnreadable, 503, `{"error":"totp_unreadable"}`},
		{errors.New("x"), 500, `{"error":"internal"}`},
	} {
		rec := httptest.NewRecorder()
		WriteError(rec, c.err)
		var got, want any
		json.Unmarshal(rec.Body.Bytes(), &got)
		json.Unmarshal([]byte(c.body), &want)
		if rec.Code != c.status || !jsonEqual(got, want) {
			t.Errorf("%v: %d %s", c.err, rec.Code, rec.Body)
		}
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func TestIPIgnoresForwardedHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := IP(r); got != "10.0.0.1" {
		t.Fatal(got)
	}
}

// Edge case: a malformed code is a guess against the account, not only the IP.
func TestCheckMalformedCodeCountsForAccount(t *testing.T) {
	a := &fakeAttempt{ok: true}
	if _, err := newChecker(a).Check(context.Background(), &user.User{ID: 1}, sealed(t, 1), "12ab", "ip"); !errors.Is(err, ErrInvalid) || a.calls != 1 {
		t.Fatalf("err %v account attempts %d", err, a.calls)
	}
}
