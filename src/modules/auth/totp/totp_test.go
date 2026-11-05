package totp

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"
)

var rfcSecret = []byte("12345678901234567890")

func TestCodeRFC6238(t *testing.T) {
	for _, c := range []struct {
		unix int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1234567890, "89005924"}, {20000000000, "65353130"}} {
		if got := Code(rfcSecret, uint64(c.unix/Step), 8); got != c.want {
			t.Errorf("T=%d: got %s want %s", c.unix, got, c.want)
		}
	}
	if got := Code(rfcSecret, 1, Digits); got != "287082" {
		t.Errorf("6 digits: %s", got)
	}
}

func TestMatchWindowAndReplay(t *testing.T) {
	now := time.Unix(1111111109, 0)
	cur := now.Unix() / Step
	code := func(c int64) string { return Code(rfcSecret, uint64(c), Digits) }

	for _, d := range []int64{-1, 0, 1} {
		got, ok := Match(rfcSecret, code(cur+d), now, 0)
		if !ok || got != cur+d {
			t.Errorf("drift %d: %d %v", d, got, ok)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := Match(rfcSecret, code(cur+d), now, 0); ok {
			t.Errorf("drift %d accepted", d)
		}
	}
	if _, ok := Match(rfcSecret, code(cur), now, cur); ok {
		t.Error("replay of last accepted step accepted")
	}
	if _, ok := Match(rfcSecret, code(cur-1), now, cur); ok {
		t.Error("earlier step after last accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", " " + code(cur)[1:]} {
		if _, ok := Match(rfcSecret, bad, now, 0); ok {
			t.Errorf("malformed %q accepted", bad)
		}
	}
}

func TestURI(t *testing.T) {
	secret := bytes.Repeat([]byte{0xff}, 20)
	u, err := url.Parse(URI("ana@x.com", secret))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Guardian:ana@x.com" {
		t.Fatalf("uri %s", u)
	}
	q := u.Query()
	if q.Get("secret") != strings.Repeat("7", 32) || q.Get("issuer") != "Guardian" {
		t.Fatalf("query %v", q)
	}
}

func TestSealBindsUser(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	blob, err := Seal(key, 7, rfcSecret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, rfcSecret) {
		t.Fatal("plaintext in blob")
	}
	got, err := Open(key, 7, blob)
	if err != nil || !bytes.Equal(got, rfcSecret) {
		t.Fatalf("open: %v", err)
	}
	if _, err := Open(key, 8, blob); err == nil {
		t.Fatal("blob opened for another user")
	}
}

func TestLimiterLocksIPAfterThreeFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(func() time.Time { return now })
	l.Fail("1.1.1.1")
	l.Fail("1.1.1.1")
	if d := l.LockedFor("1.1.1.1"); d != 0 {
		t.Fatalf("locked after 2: %v", d)
	}
	l.Fail("1.1.1.1")
	if d := l.LockedFor("1.1.1.1"); d != 10*time.Minute {
		t.Fatalf("after 3: %v", d)
	}
	if d := l.LockedFor("2.2.2.2"); d != 0 {
		t.Fatalf("other ip locked: %v", d)
	}
	now = now.Add(10 * time.Minute)
	if d := l.LockedFor("1.1.1.1"); d != 0 {
		t.Fatalf("still locked after 10m: %v", d)
	}
	l.Fail("1.1.1.1")
	l.Fail("1.1.1.1")
	if d := l.LockedFor("1.1.1.1"); d != 0 {
		t.Fatalf("counter not reset after lock expired: %v", d)
	}
}

func TestLimiterWindowExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(func() time.Time { return now })
	l.Fail("ip")
	l.Fail("ip")
	now = now.Add(10 * time.Minute)
	l.Fail("ip")
	if d := l.LockedFor("ip"); d != 0 {
		t.Fatalf("failures older than 10m counted: %v", d)
	}
}
