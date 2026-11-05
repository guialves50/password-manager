package generator

import (
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
)

const (
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower   = "abcdefghijklmnopqrstuvwxyz"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.?/"
)

func TestGenerateClassesAndAlphabet(t *testing.T) {
	all := upper + lower + digits + symbols
	for i := range 10000 {
		n := 8 + i%121
		pw, err := Generate(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != n {
			t.Fatalf("len %d, want %d", len(pw), n)
		}
		for _, c := range pw {
			if !strings.ContainsRune(all, c) {
				t.Fatalf("%q outside alphabet in %q", c, pw)
			}
		}
		for _, class := range []string{upper, lower, digits, symbols} {
			if !strings.ContainsAny(pw, class) {
				t.Fatalf("%q misses class %q", pw, class)
			}
		}
	}
}

func TestGenerateBounds(t *testing.T) {
	for _, n := range []int{8, 20, 128} {
		if pw, err := Generate(n); err != nil || len(pw) != n {
			t.Errorf("%d: %q %v", n, pw, err)
		}
	}
	for _, n := range []int{-1, 0, 7, 129, 1024} {
		if pw, err := Generate(n); !errors.Is(err, vaulterrors.ErrGenLength) || pw != "" {
			t.Errorf("%d: %q %v", n, pw, err)
		}
	}
}

func TestGenerateUniform(t *testing.T) {
	all := upper + lower + digits + symbols
	if len(all) != 86 {
		t.Fatalf("alphabet size %d", len(all))
	}
	counts := map[rune]int{}
	total := 0
	for range 4000 {
		pw, _ := Generate(128)
		for _, c := range pw {
			counts[c]++
			total++
		}
	}
	want := float64(total) / 86
	for _, c := range all {
		if got := float64(counts[c]); got < want*0.9 || got > want*1.1 {
			t.Errorf("%q: %v, want ~%v", c, got, want)
		}
	}
}

func TestGenerateRandFailure(t *testing.T) {
	orig := reader
	reader = failing{}
	t.Cleanup(func() { reader = orig })
	if pw, err := Generate(20); err == nil || pw != "" {
		t.Fatalf("%q %v", pw, err)
	}
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestGenerateUsesCryptoRand(t *testing.T) {
	if reader != rand.Reader {
		t.Fatal("generator must read from crypto/rand.Reader")
	}
}

func TestGenerateUniformPerPosition(t *testing.T) {
	const samples, n = 20000, 20
	classes := []string{upper, lower, digits, symbols}
	counts := make([][4]int, n)
	for range samples {
		pw, _ := Generate(n)
		for i, c := range pw {
			for k, class := range classes {
				if strings.ContainsRune(class, c) {
					counts[i][k]++
				}
			}
		}
	}
	for i := range n {
		for k, class := range classes {
			want := float64(samples) * float64(len(class)) / 86
			if got := float64(counts[i][k]); got < want*0.85 || got > want*1.15 {
				t.Errorf("position %d class %q: %v, want ~%v", i, class[:1], got, want)
			}
		}
	}
}
