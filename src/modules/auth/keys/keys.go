package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

var DefaultParams = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

func Derive(secret, salt []byte, p Params) []byte {
	return argon2.IDKey(secret, salt, p.Time, p.MemoryKiB, p.Threads, 32)
}

func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func Zero(b []byte) {
	clear(b)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Seal(key, plaintext, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce, err := Random(a.NonceSize())
	if err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plaintext, aad), nil
}

func Open(key, blob, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < a.NonceSize() {
		return nil, errors.New("blob too short")
	}
	return a.Open(nil, blob[:a.NonceSize()], blob[a.NonceSize():], aad)
}

func NewRecoveryKey() (string, error) {
	b, err := Random(20)
	if err != nil {
		return "", err
	}
	s := base32.StdEncoding.EncodeToString(b)
	groups := make([]string, 0, 8)
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:i+4])
	}
	return strings.Join(groups, "-"), nil
}

func NormalizeRecoveryKey(s string) []byte {
	out := make([]byte, 0, 32)
	for _, r := range s {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		out = append(out, byte(unicode.ToUpper(r)))
	}
	return out
}
