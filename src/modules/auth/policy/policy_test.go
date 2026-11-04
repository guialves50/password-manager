package policy

import (
	"strings"
	"testing"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
)

func TestNormalizeEmail(t *testing.T) {
	got, err := NormalizeEmail("  Foo.Bar@Example.COM \n")
	if err != nil || got != "foo.bar@example.com" {
		t.Fatalf("got %q, %v", got, err)
	}
	local := strings.Repeat("a", 64)
	ok254 := local + "@" + strings.Repeat("b", 254-65-4) + ".com"
	if len(ok254) != 254 {
		t.Fatalf("setup len %d", len(ok254))
	}
	if got, err := NormalizeEmail(ok254); err != nil || got != ok254 {
		t.Fatalf("254 chars rejected: %v", err)
	}
	for _, in := range []string{"", "   ", "semarroba.com", "a@", "Nome <x@y.com>", "<x@y.com>", ok254 + "c"} {
		if _, err := NormalizeEmail(in); err != autherrors.ErrInvalidEmail {
			t.Errorf("%q: got %v", in, err)
		}
	}
}

func TestCheckMasterPassword(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"Abcdefg", autherrors.ErrPasswordLength},
		{"Abcdefgh", nil},
		{"A" + strings.Repeat("b", 127), nil},
		{"A" + strings.Repeat("b", 128), autherrors.ErrPasswordLength},
		{"", autherrors.ErrPasswordLength},
		{"abcdefgh", autherrors.ErrPasswordCase},
		{"ABCDEFGH", autherrors.ErrPasswordCase},
		{"12345678", autherrors.ErrPasswordCase},
		{"Éabcdefg", nil},
		{"éABCDEFG", nil},
		{"Éabcdef", autherrors.ErrPasswordLength},
		{"É" + strings.Repeat("é", 127), nil},
	}
	for _, c := range cases {
		if got := CheckMasterPassword([]byte(c.in)); got != c.want {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}
}
