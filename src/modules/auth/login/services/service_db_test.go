package services

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

type fakeRepo struct {
	u        *user.User
	findErr  error
	queried  string
	failures []uint64
	resets   []uint64
}

func (f *fakeRepo) FindByEmail(_ context.Context, email string) (*user.User, error) {
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

func (f *fakeRepo) ResetFailures(_ context.Context, id uint64) error {
	f.resets = append(f.resets, id)
	return nil
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

func seedUser(t *testing.T, email, pw string) (*user.User, []byte) {
	t.Helper()
	vk, _ := keys.Random(32)
	salt, _ := keys.Random(16)
	blob, err := keys.Seal(keys.Derive([]byte(pw), salt, testParams), vk, []byte("pm/master/v1|"+email))
	if err != nil {
		t.Fatal(err)
	}
	return &user.User{
		ID: 42, Email: email,
		KDFTime: testParams.Time, KDFMemoryKiB: testParams.MemoryKiB, KDFThreads: testParams.Threads,
		MasterSalt: salt, MasterWrappedKey: blob,
	}, vk
}

func newService(repo *fakeRepo) (*DBService, *deriveSpy) {
	spy := &deriveSpy{}
	return &DBService{Repo: repo, Params: testParams, Derive: spy.derive}, spy
}

func TestDBLoginSuccess(t *testing.T) {
	u, vk := seedUser(t, "alice@example.com", "SenhaForte1")
	u.FailedAttempts = 3
	repo := &fakeRepo{u: u}
	svc, spy := newService(repo)
	in := dto.Input{Email: " Alice@Example.com ", Password: []byte("SenhaForte1")}

	s, err := svc.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if s.UserID != 42 || s.Email != "alice@example.com" || !bytes.Equal(s.VaultKey, vk) {
		t.Fatalf("session %+v", s)
	}
	if repo.queried != "alice@example.com" || len(repo.resets) != 1 || repo.resets[0] != 42 || len(repo.failures) != 0 {
		t.Fatalf("queried %q resets %v failures %v", repo.queried, repo.resets, repo.failures)
	}
	if spy.calls != 1 {
		t.Fatalf("derive calls %d", spy.calls)
	}
	if !bytes.Equal(in.Password, make([]byte, len(in.Password))) {
		t.Fatal("password not zeroed")
	}
}

func TestDBLoginWrongPasswordRecordsFailure(t *testing.T) {
	u, _ := seedUser(t, "alice@example.com", "SenhaForte1")
	repo := &fakeRepo{u: u}
	svc, spy := newService(repo)

	s, err := svc.Login(context.Background(), dto.Input{Email: "alice@example.com", Password: []byte("SenhaErrada1")})
	if s != nil || err != autherrors.ErrInvalidCredentials {
		t.Fatalf("got %v, %v", s, err)
	}
	if len(repo.failures) != 1 || repo.failures[0] != 42 || len(repo.resets) != 0 || spy.calls != 1 {
		t.Fatalf("failures %v resets %v derive %d", repo.failures, repo.resets, spy.calls)
	}
}

func TestDBLoginBlobBoundToEmail(t *testing.T) {
	u, _ := seedUser(t, "alice@example.com", "SenhaForte1")
	u.Email = "bob@example.com"
	repo := &fakeRepo{u: u}
	svc, _ := newService(repo)

	_, err := svc.Login(context.Background(), dto.Input{Email: "bob@example.com", Password: []byte("SenhaForte1")})
	if err != autherrors.ErrInvalidCredentials || len(repo.failures) != 1 {
		t.Fatalf("err %v failures %v", err, repo.failures)
	}
}

func TestDBLoginUnknownEmailRunsDummyDerive(t *testing.T) {
	for _, email := range []string{"ghost@example.com", "not-an-email"} {
		repo := &fakeRepo{}
		svc, spy := newService(repo)
		s, err := svc.Login(context.Background(), dto.Input{Email: email, Password: []byte("SenhaForte1")})
		if s != nil || err != autherrors.ErrInvalidCredentials {
			t.Fatalf("%s: got %v, %v", email, s, err)
		}
		if spy.calls != 1 || spy.params[0] != testParams {
			t.Fatalf("%s: derive calls %d params %v", email, spy.calls, spy.params)
		}
		if len(repo.failures) != 0 || len(repo.resets) != 0 {
			t.Fatalf("%s: failures %v resets %v", email, repo.failures, repo.resets)
		}
	}
}

func TestDBLoginLockedSkipsDerive(t *testing.T) {
	cases := []struct {
		remaining time.Duration
		want      int
	}{
		{14*time.Minute + 30*time.Second, 15},
		{61 * time.Second, 2},
		{10 * time.Second, 1},
	}
	for _, c := range cases {
		u, _ := seedUser(t, "alice@example.com", "SenhaForte1")
		until := time.Now().Add(c.remaining)
		u.LockedUntil = &until
		repo := &fakeRepo{u: u}
		svc, spy := newService(repo)

		s, err := svc.Login(context.Background(), dto.Input{Email: "alice@example.com", Password: []byte("SenhaForte1")})
		var locked *autherrors.LockedError
		if s != nil || !errors.As(err, &locked) || locked.Minutes != c.want {
			t.Fatalf("%v: got %v, %v", c.remaining, s, err)
		}
		if spy.calls != 0 || len(repo.failures) != 0 || len(repo.resets) != 0 {
			t.Fatalf("%v: derive %d failures %v resets %v", c.remaining, spy.calls, repo.failures, repo.resets)
		}
	}
}

func TestDBLoginExpiredLockAllowsLogin(t *testing.T) {
	u, _ := seedUser(t, "alice@example.com", "SenhaForte1")
	past := time.Now().Add(-time.Minute)
	u.LockedUntil = &past
	u.FailedAttempts = 5
	repo := &fakeRepo{u: u}
	svc, _ := newService(repo)

	if _, err := svc.Login(context.Background(), dto.Input{Email: "alice@example.com", Password: []byte("SenhaForte1")}); err != nil {
		t.Fatal(err)
	}
	if len(repo.resets) != 1 {
		t.Fatalf("resets %v", repo.resets)
	}
}

func TestDBLoginRepoErrorPropagates(t *testing.T) {
	boom := errors.New("db down")
	svc, _ := newService(&fakeRepo{findErr: boom})
	if _, err := svc.Login(context.Background(), dto.Input{Email: "alice@example.com", Password: []byte("SenhaForte1")}); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
