package totp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/server/httpx"
)

var (
	ErrInvalid = errors.New("totp: invalid code")
	// ErrUnreadable: the stored secret doesn't open under this server's key
	// (PM_SERVER_SECRET changed or unset). Not the user's guess, so not counted.
	ErrUnreadable = errors.New("totp: stored secret unreadable")
)

type attempter interface {
	TOTPAttempt(ctx context.Context, id uint64, now time.Time) (bool, error)
}

// Checker applies the IP limiter, the per-account lock and anti-replay
// around one code guess against blob (the user's active or pending secret).
type Checker struct {
	Users   attempter
	Limiter *Limiter
	Key     []byte
	Now     func() time.Time
}

func (c *Checker) Check(ctx context.Context, u *user.User, blob []byte, code, ip string) (int64, error) {
	now := c.Now()
	if d := c.Limiter.LockedFor(ip); d > 0 {
		return 0, locked(d)
	}
	if u.TOTPLockedUntil != nil && u.TOTPLockedUntil.After(now) {
		return 0, locked(u.TOTPLockedUntil.Sub(now))
	}
	secret, err := Open(c.Key, u.ID, blob)
	if err != nil {
		return 0, ErrUnreadable
	}
	defer clear(secret)
	ok, err := c.Users.TOTPAttempt(ctx, u.ID, now)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, locked(user.TOTPLockDuration)
	}
	counter, ok := Match(secret, code, now, u.TOTPLastCounter)
	if !ok {
		c.Limiter.Fail(ip)
		return 0, ErrInvalid
	}
	return counter, nil
}

func locked(d time.Duration) error {
	return &autherrors.LockedError{Minutes: int((d + time.Minute - 1) / time.Minute)}
}

func WriteError(w http.ResponseWriter, err error) {
	var l *autherrors.LockedError
	switch {
	case errors.As(err, &l):
		httpx.Locked(w, l.Minutes)
	case errors.Is(err, ErrInvalid):
		httpx.Error(w, http.StatusUnauthorized, "invalid_totp")
	case errors.Is(err, ErrUnreadable):
		httpx.Error(w, http.StatusServiceUnavailable, "totp_unreadable")
	default:
		httpx.Error(w, http.StatusInternalServerError, "internal")
	}
}

// IP is the connection's address; forwarded headers are ignored because
// clients can forge them.
func IP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
