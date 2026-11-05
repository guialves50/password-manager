//go:build integration

package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/database"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/recover/repository"
	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/user"
	"gorm.io/gorm"
)

func seedAuthUser(t *testing.T, db *gorm.DB, email string) *user.User {
	t.Helper()
	until := time.Now().Add(10 * time.Minute)
	u := &user.User{
		Email: email, KDFTime: 3, KDFMemoryKiB: 65536, KDFThreads: 4,
		MasterSalt: []byte("s"), MasterWrappedKey: []byte("m"),
		RecoverySalt: []byte("r"), RecoveryWrappedKey: []byte("k"),
		AuthSalt: []byte("as"), AuthHash: []byte("ah"),
		RecoveryAuthSalt: []byte("ras"), RecoveryAuthHash: []byte("rah"),
		FailedAttempts: 5, LockedUntil: &until,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func next(tag string) *user.User {
	return &user.User{
		MasterSalt: []byte("s" + tag), MasterWrappedKey: []byte("m" + tag),
		AuthSalt: []byte("as" + tag), AuthHash: []byte("ah" + tag),
		RecoverySalt: []byte("r" + tag), RecoveryWrappedKey: []byte("k" + tag),
		RecoveryAuthSalt: []byte("ras" + tag), RecoveryAuthHash: []byte("rah" + tag),
	}
}

func TestRotateAuthReplacesKeysAndDeletesSessions(t *testing.T) {
	db := database.TestTx(t)
	ctx := context.Background()
	u := seedAuthUser(t, db, "rotate-auth@example.com")
	other := seedAuthUser(t, db, "rotate-other@example.com")
	sessions := session.NewRepository(db)
	for _, id := range []uint64{u.ID, u.ID, other.ID} {
		if _, err := sessions.Create(ctx, id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	if err := repository.New(db).RotateAuth(ctx, u.ID, []byte("rah"), next("2")); err != nil {
		t.Fatal(err)
	}
	var got user.User
	if err := db.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	fields := map[string][2]string{
		"master_salt": {string(got.MasterSalt), "s2"}, "master_wrapped_key": {string(got.MasterWrappedKey), "m2"},
		"auth_salt": {string(got.AuthSalt), "as2"}, "auth_hash": {string(got.AuthHash), "ah2"},
		"recovery_salt": {string(got.RecoverySalt), "r2"}, "recovery_wrapped_key": {string(got.RecoveryWrappedKey), "k2"},
		"recovery_auth_salt": {string(got.RecoveryAuthSalt), "ras2"}, "recovery_auth_hash": {string(got.RecoveryAuthHash), "rah2"},
	}
	for name, v := range fields {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", name, v[0], v[1])
		}
	}
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Fatalf("lockout not reset: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
	if got.Email != "rotate-auth@example.com" || got.KDFTime != 3 {
		t.Fatalf("unrelated fields changed: %+v", got)
	}
	var n, m int64
	db.Model(&session.Session{}).Where("user_id = ?", u.ID).Count(&n)
	db.Model(&session.Session{}).Where("user_id = ?", other.ID).Count(&m)
	if n != 0 || m != 1 {
		t.Fatalf("sessions left: user=%d other=%d", n, m)
	}
}

func TestRotateAuthRejectsStaleHash(t *testing.T) {
	db := database.TestTx(t)
	ctx := context.Background()
	u := seedAuthUser(t, db, "rotate-race@example.com")
	repo := repository.New(db)
	if err := repo.RotateAuth(ctx, u.ID, []byte("rah"), next("2")); err != nil {
		t.Fatal(err)
	}
	sessions := session.NewRepository(db)
	if _, err := sessions.Create(ctx, u.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := repo.RotateAuth(ctx, u.ID, []byte("rah"), next("3")); !errors.Is(err, autherrors.ErrInvalidRecovery) {
		t.Fatalf("second rotation with the stale hash: got %v", err)
	}
	var got user.User
	if err := db.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if string(got.AuthHash) != "ah2" || string(got.RecoveryAuthHash) != "rah2" || string(got.MasterWrappedKey) != "m2" {
		t.Fatalf("first recovery overwritten: %q %q", got.AuthHash, got.RecoveryAuthHash)
	}
	var n int64
	db.Model(&session.Session{}).Where("user_id = ?", u.ID).Count(&n)
	if n != 1 {
		t.Fatalf("failed rotation deleted sessions: %d left", n)
	}
	if err := repo.RotateAuth(ctx, 0, []byte("rah2"), next("4")); !errors.Is(err, autherrors.ErrInvalidRecovery) {
		t.Fatalf("missing user: %v", err)
	}
}

func TestRotateAuthDisables2FA(t *testing.T) {
	db := database.TestTx(t)
	ctx := context.Background()
	u := seedAuthUser(t, db, "rotate-2fa@example.com")
	until := time.Now().Add(5 * time.Minute)
	if err := db.Model(u).Updates(map[string]any{
		"totp_secret": []byte("s"), "totp_pending": []byte("p"), "totp_last_counter": 99,
		"totp_failures": 3, "totp_locked_until": until,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := repository.New(db).RotateAuth(ctx, u.ID, []byte("rah"), next("2")); err != nil {
		t.Fatal(err)
	}
	var got user.User
	if err := db.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.TOTPSecret != nil || got.TOTPPending != nil || got.TOTPLastCounter != 0 || got.TOTPFailures != 0 || got.TOTPLockedUntil != nil {
		t.Fatalf("2fa not cleared: %+v", got)
	}
}
