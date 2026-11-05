package generator

import (
	"crypto/rand"
	"math/big"
	"strings"

	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
)

const (
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.?/"
	Default  = 20
	Min      = 8
	Max      = 128
)

var (
	reader  = rand.Reader
	classes = []string{alphabet[:26], alphabet[26:52], alphabet[52:62], alphabet[62:]}
)

func Generate(n int) (string, error) {
	if n < Min || n > Max {
		return "", vaulterrors.ErrGenLength
	}
	size := big.NewInt(int64(len(alphabet)))
	b := make([]byte, n)
	for {
		for i := range b {
			k, err := rand.Int(reader, size)
			if err != nil {
				return "", err
			}
			b[i] = alphabet[k.Int64()]
		}
		if complete(string(b)) {
			return string(b), nil
		}
	}
}

func complete(pw string) bool {
	for _, c := range classes {
		if !strings.ContainsAny(pw, c) {
			return false
		}
	}
	return true
}
