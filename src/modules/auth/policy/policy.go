package policy

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
)

func NormalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 254 {
		return "", autherrors.ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Name != "" || addr.Address != s {
		return "", autherrors.ErrInvalidEmail
	}
	return s, nil
}

func CheckMasterPassword(p []byte) error {
	if n := utf8.RuneCount(p); n < 8 || n > 128 {
		return autherrors.ErrPasswordLength
	}
	var upper, lower bool
	for _, r := range string(p) {
		upper = upper || unicode.IsUpper(r)
		lower = lower || unicode.IsLower(r)
	}
	if !upper || !lower {
		return autherrors.ErrPasswordCase
	}
	return nil
}
