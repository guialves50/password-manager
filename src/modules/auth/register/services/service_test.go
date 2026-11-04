package services

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

var testParams = keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

type fakeRepo struct {
	got   *user.User
	calls int
	err   error
}

func (f *fakeRepo) Create(_ context.Context, u *user.User) error {
	f.calls++
	f.got = u
	return f.err
}

func input(email, pw, confirm string) dto.Input {
	return dto.Input{Email: email, Password: []byte(pw), Confirm: []byte(confirm)}
}

func TestRegisterHappyPath(t *testing.T) {
	repo := &fakeRepo{}
	svc := &Service{Repo: repo, Params: testParams}
	in := input("  Alice@Example.COM ", "SenhaForte1", "SenhaForte1")

	out, err := svc.Register(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$`).MatchString(out.RecoveryKey) {
		t.Fatalf("recovery key %q", out.RecoveryKey)
	}
	u := repo.got
	if repo.calls != 1 || u == nil {
		t.Fatalf("create calls %d", repo.calls)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("email %q", u.Email)
	}
	if u.KDFTime != testParams.Time || u.KDFMemoryKiB != testParams.MemoryKiB || u.KDFThreads != testParams.Threads {
		t.Fatalf("params %d %d %d", u.KDFTime, u.KDFMemoryKiB, u.KDFThreads)
	}
	if len(u.MasterSalt) != 16 || len(u.RecoverySalt) != 16 || bytes.Equal(u.MasterSalt, u.RecoverySalt) {
		t.Fatalf("salts %x %x", u.MasterSalt, u.RecoverySalt)
	}

	masterKEK := keys.Derive([]byte("SenhaForte1"), u.MasterSalt, testParams)
	v1, err := keys.Open(masterKEK, u.MasterWrappedKey, []byte("pm/master/v1|alice@example.com"))
	if err != nil {
		t.Fatalf("open master: %v", err)
	}
	recKEK := keys.Derive(keys.NormalizeRecoveryKey(out.RecoveryKey), u.RecoverySalt, testParams)
	v2, err := keys.Open(recKEK, u.RecoveryWrappedKey, []byte("pm/recovery/v1|alice@example.com"))
	if err != nil {
		t.Fatalf("open recovery: %v", err)
	}
	if len(v1) != 32 || !bytes.Equal(v1, v2) || bytes.Equal(v1, make([]byte, 32)) {
		t.Fatalf("vault keys differ or invalid: %x %x", v1, v2)
	}
	if _, err := keys.Open(masterKEK, u.MasterWrappedKey, []byte("pm/master/v1|bob@example.com")); err == nil {
		t.Fatal("blob opened with another email as AAD")
	}

	secrets := [][]byte{[]byte("SenhaForte1"), []byte(out.RecoveryKey), keys.NormalizeRecoveryKey(out.RecoveryKey), v1}
	for _, field := range [][]byte{[]byte(u.Email), u.MasterSalt, u.MasterWrappedKey, u.RecoverySalt, u.RecoveryWrappedKey} {
		for _, s := range secrets {
			if bytes.Contains(field, s) {
				t.Fatalf("secret %q stored in clear", s)
			}
		}
	}
	if !bytes.Equal(in.Password, make([]byte, len(in.Password))) || !bytes.Equal(in.Confirm, make([]byte, len(in.Confirm))) {
		t.Fatal("input secrets not zeroed")
	}
}

func TestRegisterUniqueKeysPerUser(t *testing.T) {
	repo := &fakeRepo{}
	svc := &Service{Repo: repo, Params: testParams}
	out1, _ := svc.Register(context.Background(), input("a@example.com", "SenhaForte1", "SenhaForte1"))
	u1 := repo.got
	out2, _ := svc.Register(context.Background(), input("b@example.com", "SenhaForte1", "SenhaForte1"))
	u2 := repo.got
	if out1.RecoveryKey == out2.RecoveryKey || bytes.Equal(u1.MasterSalt, u2.MasterSalt) {
		t.Fatal("random material repeated across users")
	}
}

func TestRegisterValidationNeverCallsRepo(t *testing.T) {
	cases := []struct {
		name string
		in   dto.Input
		want error
	}{
		{"empty email", input("", "SenhaForte1", "SenhaForte1"), autherrors.ErrInvalidEmail},
		{"no at", input("alice.example.com", "SenhaForte1", "SenhaForte1"), autherrors.ErrInvalidEmail},
		{"255 chars", input(strings.Repeat("a", 243)+"@example.com", "SenhaForte1", "SenhaForte1"), autherrors.ErrInvalidEmail},
		{"7 chars", input("a@example.com", "Senha12", "Senha12"), autherrors.ErrPasswordLength},
		{"129 chars", input("a@example.com", "A"+strings.Repeat("a", 128), "A"+strings.Repeat("a", 128)), autherrors.ErrPasswordLength},
		{"lowercase only", input("a@example.com", "senhafraca", "senhafraca"), autherrors.ErrPasswordCase},
		{"uppercase only", input("a@example.com", "SENHAFRACA", "SENHAFRACA"), autherrors.ErrPasswordCase},
		{"mismatch", input("a@example.com", "SenhaForte1", "SenhaForte2"), autherrors.ErrPasswordMismatch},
	}
	for _, c := range cases {
		repo := &fakeRepo{}
		svc := &Service{Repo: repo, Params: testParams}
		_, err := svc.Register(context.Background(), c.in)
		if err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if repo.calls != 0 {
			t.Errorf("%s: repo called", c.name)
		}
	}
}

func TestRegisterEmailTaken(t *testing.T) {
	repo := &fakeRepo{err: autherrors.ErrEmailTaken}
	svc := &Service{Repo: repo, Params: testParams}
	out, err := svc.Register(context.Background(), input("a@example.com", "SenhaForte1", "SenhaForte1"))
	if !errors.Is(err, autherrors.ErrEmailTaken) || out.RecoveryKey != "" {
		t.Fatalf("got %q, %v", out.RecoveryKey, err)
	}
}
