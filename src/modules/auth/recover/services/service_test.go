package services

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

var testParams = keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

type rotation struct {
	id                                                           uint64
	verified, masterSalt, masterBlob, recoverySalt, recoveryBlob []byte
}

type fakeRepo struct {
	u         *user.User
	findErr   error
	queried   string
	finds     int
	failures  []uint64
	rotated   []rotation
	rotateErr error
}

func (f *fakeRepo) FindByEmail(_ context.Context, email string) (*user.User, error) {
	f.finds++
	f.queried = email
	if f.u == nil || f.u.Email != email {
		return nil, f.findErr
	}
	return f.u, f.findErr
}

func (f *fakeRepo) RecordFailure(_ context.Context, id uint64) error {
	f.failures = append(f.failures, id)
	return nil
}

func (f *fakeRepo) RotateKeys(_ context.Context, id uint64, verified, ms, mb, rs, rb []byte) error {
	f.rotated = append(f.rotated, rotation{id, verified, ms, mb, rs, rb})
	return f.rotateErr
}

type deriveSpy struct {
	calls  int
	params []keys.Params
}

func (d *deriveSpy) derive(secret, salt []byte, p keys.Params) []byte {
	d.calls++
	d.params = append(d.params, p)
	return keys.Derive(secret, salt, p)
}

func seedUser(t *testing.T, email, pw string) (*user.User, []byte, string) {
	t.Helper()
	vk, _ := keys.Random(32)
	ms, _ := keys.Random(16)
	rs, _ := keys.Random(16)
	rk, _ := keys.NewRecoveryKey()
	mb, err := keys.Seal(keys.Derive([]byte(pw), ms, testParams), vk, []byte("pm/master/v1|"+email))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := keys.Seal(keys.Derive(keys.NormalizeRecoveryKey([]byte(rk)), rs, testParams), vk, []byte("pm/recovery/v1|"+email))
	if err != nil {
		t.Fatal(err)
	}
	return &user.User{
		ID: 42, Email: email,
		KDFTime: testParams.Time, KDFMemoryKiB: testParams.MemoryKiB, KDFThreads: testParams.Threads,
		MasterSalt: ms, MasterWrappedKey: mb, RecoverySalt: rs, RecoveryWrappedKey: rb,
	}, vk, rk
}

func newService(repo *fakeRepo) (*Service, *deriveSpy) {
	spy := &deriveSpy{}
	return &Service{Repo: repo, Params: keys.Params{Time: 2, MemoryKiB: 8 * 1024, Threads: 1}, Derive: spy.derive}, spy
}

func input(email, rk, pw, confirm string) dto.Input {
	return dto.Input{Email: email, RecoveryKey: []byte(rk), Password: []byte(pw), Confirm: []byte(confirm)}
}

func TestRecoverRotatesKeys(t *testing.T) {
	u, vk, oldKey := seedUser(t, "alice@example.com", "SenhaAntiga1")
	u.FailedAttempts = 3
	oldMasterSalt, oldRecoverySalt := u.MasterSalt, u.RecoverySalt
	repo := &fakeRepo{u: u}
	svc, _ := newService(repo)
	messy := " " + strings.ToLower(strings.ReplaceAll(oldKey, "-", " ")) + " "
	in := input(" Alice@Example.com ", messy, "SenhaNova1", "SenhaNova1")

	out, err := svc.Recover(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$`).MatchString(out.RecoveryKey) || out.RecoveryKey == oldKey {
		t.Fatalf("new recovery key %q (old %q)", out.RecoveryKey, oldKey)
	}
	if repo.queried != "alice@example.com" || len(repo.rotated) != 1 || len(repo.failures) != 0 {
		t.Fatalf("queried %q rotated %d failures %v", repo.queried, len(repo.rotated), repo.failures)
	}
	r := repo.rotated[0]
	if r.id != 42 || len(r.masterSalt) != 16 || len(r.recoverySalt) != 16 {
		t.Fatalf("rotation %+v", r)
	}
	if !bytes.Equal(r.verified, u.RecoveryWrappedKey) {
		t.Fatal("rotation not conditioned on the verified recovery blob")
	}
	if bytes.Equal(r.masterSalt, oldMasterSalt) || bytes.Equal(r.recoverySalt, oldRecoverySalt) || bytes.Equal(r.masterSalt, r.recoverySalt) {
		t.Fatal("salts not renewed")
	}

	v1, err := keys.Open(keys.Derive([]byte("SenhaNova1"), r.masterSalt, testParams), r.masterBlob, []byte("pm/master/v1|alice@example.com"))
	if err != nil {
		t.Fatalf("new master blob: %v", err)
	}
	v2, err := keys.Open(keys.Derive(keys.NormalizeRecoveryKey([]byte(out.RecoveryKey)), r.recoverySalt, testParams), r.recoveryBlob, []byte("pm/recovery/v1|alice@example.com"))
	if err != nil {
		t.Fatalf("new recovery blob: %v", err)
	}
	if !bytes.Equal(v1, vk) || !bytes.Equal(v2, vk) {
		t.Fatal("vault key changed")
	}
	if _, err := keys.Open(keys.Derive([]byte("SenhaAntiga1"), r.masterSalt, testParams), r.masterBlob, []byte("pm/master/v1|alice@example.com")); err == nil {
		t.Fatal("old password opens new master blob")
	}
	if _, err := keys.Open(keys.Derive(keys.NormalizeRecoveryKey([]byte(oldKey)), r.recoverySalt, testParams), r.recoveryBlob, []byte("pm/recovery/v1|alice@example.com")); err == nil {
		t.Fatal("old recovery key opens new recovery blob")
	}

	for _, field := range [][]byte{r.masterSalt, r.masterBlob, r.recoverySalt, r.recoveryBlob} {
		for _, s := range [][]byte{[]byte("SenhaNova1"), []byte(out.RecoveryKey), keys.NormalizeRecoveryKey([]byte(out.RecoveryKey)), vk} {
			if bytes.Contains(field, s) {
				t.Fatalf("secret %q stored in clear", s)
			}
		}
	}
	for _, b := range [][]byte{in.RecoveryKey, in.Password, in.Confirm} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("input secrets not zeroed")
		}
	}
}

func TestRecoverPolicyErrorsTouchNothing(t *testing.T) {
	cases := []struct {
		name string
		in   dto.Input
		want error
	}{
		{"short", input("alice@example.com", "x", "Senha12", "Senha12"), autherrors.ErrPasswordLength},
		{"long", input("alice@example.com", "x", "A"+strings.Repeat("a", 128), "A"+strings.Repeat("a", 128)), autherrors.ErrPasswordLength},
		{"lowercase", input("alice@example.com", "x", "senhafraca", "senhafraca"), autherrors.ErrPasswordCase},
		{"uppercase", input("alice@example.com", "x", "SENHAFRACA", "SENHAFRACA"), autherrors.ErrPasswordCase},
		{"mismatch", input("alice@example.com", "x", "SenhaNova1", "SenhaNova2"), autherrors.ErrPasswordMismatch},
	}
	for _, c := range cases {
		u, _, _ := seedUser(t, "alice@example.com", "SenhaAntiga1")
		repo := &fakeRepo{u: u}
		svc, spy := newService(repo)
		_, err := svc.Recover(context.Background(), c.in)
		if err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if repo.finds != 0 || spy.calls != 0 || len(repo.failures) != 0 || len(repo.rotated) != 0 {
			t.Errorf("%s: finds %d derive %d failures %v rotated %d", c.name, repo.finds, spy.calls, repo.failures, len(repo.rotated))
		}
	}
}

func TestRecoverWrongKeyRecordsFailure(t *testing.T) {
	u, _, _ := seedUser(t, "alice@example.com", "SenhaAntiga1")
	other, _ := keys.NewRecoveryKey()
	repo := &fakeRepo{u: u}
	svc, spy := newService(repo)

	out, err := svc.Recover(context.Background(), input("alice@example.com", other, "SenhaNova1", "SenhaNova1"))
	if err != autherrors.ErrInvalidRecovery || out.RecoveryKey != "" {
		t.Fatalf("got %q, %v", out.RecoveryKey, err)
	}
	if len(repo.failures) != 1 || repo.failures[0] != 42 || len(repo.rotated) != 0 {
		t.Fatalf("failures %v rotated %d", repo.failures, len(repo.rotated))
	}
	if spy.calls != 1 || spy.params[0] != testParams {
		t.Fatalf("derive calls %d params %v", spy.calls, spy.params)
	}
}

func TestRecoverBlobBoundToEmail(t *testing.T) {
	u, _, rk := seedUser(t, "alice@example.com", "SenhaAntiga1")
	u.Email = "bob@example.com"
	repo := &fakeRepo{u: u}
	svc, _ := newService(repo)

	if _, err := svc.Recover(context.Background(), input("bob@example.com", rk, "SenhaNova1", "SenhaNova1")); err != autherrors.ErrInvalidRecovery || len(repo.failures) != 1 {
		t.Fatalf("err %v failures %v", err, repo.failures)
	}
}

func TestRecoverUnknownEmailRunsDummyDerive(t *testing.T) {
	for _, email := range []string{"ghost@example.com", "not-an-email"} {
		repo := &fakeRepo{}
		svc, spy := newService(repo)
		_, err := svc.Recover(context.Background(), input(email, "AAAA-BBBB", "SenhaNova1", "SenhaNova1"))
		if err != autherrors.ErrInvalidRecovery {
			t.Fatalf("%s: got %v", email, err)
		}
		if spy.calls != 1 || spy.params[0] != svc.Params {
			t.Fatalf("%s: derive calls %d params %v", email, spy.calls, spy.params)
		}
		if len(repo.failures) != 0 || len(repo.rotated) != 0 {
			t.Fatalf("%s: failures %v rotated %d", email, repo.failures, len(repo.rotated))
		}
	}
}

func TestRecoverLockedSkipsDerive(t *testing.T) {
	cases := []struct {
		remaining time.Duration
		want      int
	}{
		{14*time.Minute + 30*time.Second, 15},
		{61 * time.Second, 2},
		{10 * time.Second, 1},
	}
	for _, c := range cases {
		u, _, rk := seedUser(t, "alice@example.com", "SenhaAntiga1")
		until := time.Now().Add(c.remaining)
		u.LockedUntil = &until
		repo := &fakeRepo{u: u}
		svc, spy := newService(repo)

		_, err := svc.Recover(context.Background(), input("alice@example.com", rk, "SenhaNova1", "SenhaNova1"))
		var locked *autherrors.LockedError
		if !errors.As(err, &locked) || locked.Minutes != c.want {
			t.Fatalf("%v: got %v", c.remaining, err)
		}
		if spy.calls != 0 || len(repo.failures) != 0 || len(repo.rotated) != 0 {
			t.Fatalf("%v: derive %d failures %v rotated %d", c.remaining, spy.calls, repo.failures, len(repo.rotated))
		}
	}
}

func TestRecoverRepoErrorPropagates(t *testing.T) {
	boom := errors.New("db down")
	svc, _ := newService(&fakeRepo{findErr: boom})
	if _, err := svc.Recover(context.Background(), input("alice@example.com", "x", "SenhaNova1", "SenhaNova1")); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestRecoverRotateFailureReturnsNoKey(t *testing.T) {
	u, _, oldKey := seedUser(t, "alice@example.com", "SenhaAntiga1")
	rotateErr := errors.New("0 rows")
	repo := &fakeRepo{u: u, rotateErr: rotateErr}
	svc, _ := newService(repo)

	out, err := svc.Recover(context.Background(), input("alice@example.com", oldKey, "SenhaNova1", "SenhaNova1"))
	if !errors.Is(err, rotateErr) || out.RecoveryKey != "" {
		t.Fatalf("err %v key %q", err, out.RecoveryKey)
	}
}
