package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
)

const (
	Step         = 30
	Digits       = 6
	Issuer       = "Guardian"
	MaxFailures  = 3
	LockDuration = 10 * time.Minute
)

func Code(secret []byte, counter uint64, digits int) string {
	m := hmac.New(sha1.New, secret)
	m.Write(binary.BigEndian.AppendUint64(nil, counter))
	h := m.Sum(nil)
	v := binary.BigEndian.Uint32(h[h[len(h)-1]&0xf:]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Match returns the time step the code belongs to (current ±1). Steps at or
// before last were already used and never match again.
func Match(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != Digits {
		return 0, false
	}
	t := now.Unix() / Step
	for c := t - 1; c <= t+1; c++ {
		if c > last && subtle.ConstantTimeCompare([]byte(Code(secret, uint64(c), Digits)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

func Base32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func URI(email string, secret []byte) string {
	q := url.Values{"secret": {Base32(secret)}, "issuer": {Issuer}}
	return (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + Issuer + ":" + email, RawQuery: q.Encode()}).String()
}

func aad(userID uint64) []byte {
	return []byte("pm/totp/v1|" + strconv.FormatUint(userID, 10))
}

func Seal(key []byte, userID uint64, secret []byte) ([]byte, error) {
	return keys.Seal(key, secret, aad(userID))
}

func Open(key []byte, userID uint64, blob []byte) ([]byte, error) {
	return keys.Open(key, blob, aad(userID))
}
