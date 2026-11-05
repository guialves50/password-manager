package generator

import (
	"crypto/rand"
	"errors"
	"io"
	"math"
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

func coverProb(sizes []int, n int) float64 {
	p := 0.0
	for mask := 0; mask < 1<<len(sizes); mask++ {
		left, sign := 86, 1.0
		for k, size := range sizes {
			if mask&(1<<k) != 0 {
				left -= size
				sign = -sign
			}
		}
		p += sign * math.Pow(float64(left)/86, float64(n))
	}
	return p
}

func TestGenerateUniformPerPosition(t *testing.T) {
	const samples, n = 50000, 8
	classes := []string{upper, lower, digits, symbols}
	sizes := []int{26, 26, 10, 24}
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
	all := coverProb(sizes, n)
	for k, class := range classes {
		others := append(append([]int{}, sizes[:k]...), sizes[k+1:]...)
		p := float64(sizes[k]) / 86 * coverProb(others, n-1) / all
		sigma := math.Sqrt(p * (1 - p) / samples)
		for i := range n {
			if got := float64(counts[i][k]) / samples; math.Abs(got-p) > 5*sigma {
				t.Errorf("position %d class %q: %.4f, want %.4f ± %.4f", i, class[:1], got, p, 5*sigma)
			}
		}
	}
}
