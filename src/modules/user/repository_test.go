//go:build integration

package user_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/user"
	"gorm.io/gorm"
)

func seed(t *testing.T, db *gorm.DB, email string) *user.User {
	t.Helper()
	u := &user.User{
		Email: email, KDFTime: 3, KDFMemoryKiB: 65536, KDFThreads: 4,
		MasterSalt: []byte("s"), MasterWrappedKey: []byte("m"),
		RecoverySalt: []byte("r"), RecoveryWrappedKey: []byte("k"),
		AuthSalt: []byte("as"), AuthHash: []byte("ah"),
		RecoveryAuthSalt: []byte("ras"), RecoveryAuthHash: []byte("rah"),
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	return u
}

func reload(t *testing.T, db *gorm.DB, id uint64) user.User {
	t.Helper()
	var u user.User
	if err := db.First(&u, id).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func TestFindByEmail(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	ctx := context.Background()
	want := seed(t, db, "find@example.com")

	got, err := repo.FindByEmail(ctx, "find@example.com")
	if err != nil || got == nil || got.ID != want.ID || got.Email != "find@example.com" {
		t.Fatalf("got %+v, %v", got, err)
	}
	got, err = repo.FindByEmail(ctx, "missing@example.com")
	if got != nil || err != nil {
		t.Fatalf("missing: got %+v, %v", got, err)
	}
}

func TestAttemptLocksOnFifth(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	ctx := context.Background()
	u := seed(t, db, "lock@example.com")

	for i := 1; i <= 4; i++ {
		if ok, err := repo.Attempt(ctx, u.ID); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	got := reload(t, db, u.ID)
	if got.FailedAttempts != 4 || got.LockedUntil != nil {
		t.Fatalf("after 4: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}

	before := time.Now()
	if ok, err := repo.Attempt(ctx, u.ID); err != nil || !ok {
		t.Fatal(ok, err)
	}
	got = reload(t, db, u.ID)
	if got.FailedAttempts != 5 || got.LockedUntil == nil {
		t.Fatalf("after 5: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
	if d := got.LockedUntil.Sub(before.Add(15 * time.Minute)); d < -5*time.Second || d > 5*time.Second {
		t.Fatalf("locked_until off by %v", d)
	}
	if got.LockedFor(time.Now()) <= 14*time.Minute {
		t.Fatalf("LockedFor = %v", got.LockedFor(time.Now()))
	}

	if ok, err := repo.Attempt(ctx, u.ID); err != nil || ok {
		t.Fatalf("attempt while locked: ok=%v err=%v", ok, err)
	}
	if got := reload(t, db, u.ID); got.FailedAttempts != 5 {
		t.Fatalf("locked attempt counted: %d", got.FailedAttempts)
	}

	if err := repo.ResetFailures(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got = reload(t, db, u.ID)
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Fatalf("after reset: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
}

func TestEmailMustBeLowercase(t *testing.T) {
	db := database.TestTx(t)
	u := &user.User{
		Email: "Upper@example.com", KDFTime: 3, KDFMemoryKiB: 65536, KDFThreads: 4,
		MasterSalt: []byte("s"), MasterWrappedKey: []byte("m"),
		RecoverySalt: []byte("r"), RecoveryWrappedKey: []byte("k"),
		AuthSalt: []byte("as"), AuthHash: []byte("ah"),
		RecoveryAuthSalt: []byte("ras"), RecoveryAuthHash: []byte("rah"),
	}
	if err := db.Create(u).Error; err == nil {
		t.Fatal("uppercase email accepted")
	}
}

func TestAttemptRestartsAfterExpiredLock(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	ctx := context.Background()
	u := seed(t, db, "expired@example.com")

	fail := func(n int) user.User {
		t.Helper()
		for range n {
			if ok, err := repo.Attempt(ctx, u.ID); err != nil || !ok {
				t.Fatal(ok, err)
			}
		}
		return reload(t, db, u.ID)
	}

	if got := fail(5); got.FailedAttempts != 5 || got.LockedUntil == nil {
		t.Fatalf("after 5: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
	if err := db.Model(&user.User{}).Where("id = ?", u.ID).Update("locked_until", time.Now().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	if got := fail(1); got.FailedAttempts != 1 || got.LockedUntil != nil {
		t.Fatalf("after expiry: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
	if got := fail(4); got.FailedAttempts != 5 || got.LockedFor(time.Now()) <= 14*time.Minute {
		t.Fatalf("after 4 more: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
}

func TestAuthHashColumnsRoundTrip(t *testing.T) {
	db := database.TestTx(t)
	for _, col := range []string{"auth_salt", "auth_hash", "recovery_auth_salt", "recovery_auth_hash"} {
		if !db.Migrator().HasColumn(&user.User{}, col) {
			t.Fatalf("missing column %s", col)
		}
	}
	u := &user.User{
		Email: "hashes@example.com", KDFTime: 3, KDFMemoryKiB: 65536, KDFThreads: 4,
		MasterSalt: []byte("s"), MasterWrappedKey: []byte("m"),
		RecoverySalt: []byte("r"), RecoveryWrappedKey: []byte("k"),
		AuthSalt: []byte("as"), AuthHash: []byte("ah"),
		RecoveryAuthSalt: []byte("ras"), RecoveryAuthHash: []byte("rah"),
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	got := reload(t, db, u.ID)
	if !bytes.Equal(got.AuthSalt, []byte("as")) || !bytes.Equal(got.AuthHash, []byte("ah")) ||
		!bytes.Equal(got.RecoveryAuthSalt, []byte("ras")) || !bytes.Equal(got.RecoveryAuthHash, []byte("rah")) {
		t.Fatalf("got %+v", got)
	}
}

func TestAuthHashColumnsNotNull(t *testing.T) {
	db := database.TestTx(t)
	for _, col := range []string{"auth_salt", "auth_hash", "recovery_auth_salt", "recovery_auth_hash"} {
		var nullable string
		if err := db.Raw("SELECT is_nullable FROM information_schema.columns WHERE table_name = 'users' AND column_name = ?", col).Scan(&nullable).Error; err != nil || nullable != "NO" {
			t.Errorf("%s nullable %q, %v", col, nullable, err)
		}
	}
}

func TestFindByID(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	u := seed(t, db, "byid@example.com")
	got, err := repo.FindByID(context.Background(), u.ID)
	if err != nil || got == nil || got.Email != "byid@example.com" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, err := repo.FindByID(context.Background(), u.ID+1000); got != nil || err != nil {
		t.Fatalf("missing: %+v, %v", got, err)
	}
}

func TestTOTPPendingThenActivate(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	ctx := context.Background()
	u := seed(t, db, "activate@example.com")

	if ok, err := repo.ActivateTOTP(ctx, u.ID, 5); err != nil || ok {
		t.Fatalf("activate without pending: %v %v", ok, err)
	}
	if ok, err := repo.SetTOTPPending(ctx, u.ID, []byte("p1")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := repo.SetTOTPPending(ctx, u.ID, []byte("p2")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if got := reload(t, db, u.ID); got.TOTPSecret != nil || !bytes.Equal(got.TOTPPending, []byte("p2")) {
		t.Fatalf("pending: %+v", got)
	}
	repo.TOTPAttempt(ctx, u.ID, time.Now())
	if ok, err := repo.ActivateTOTP(ctx, u.ID, 5); err != nil || !ok {
		t.Fatal(ok, err)
	}
	got := reload(t, db, u.ID)
	if !bytes.Equal(got.TOTPSecret, []byte("p2")) || got.TOTPPending != nil || got.TOTPLastCounter != 5 || got.TOTPFailures != 0 {
		t.Fatalf("active: %+v", got)
	}
	if ok, err := repo.SetTOTPPending(ctx, u.ID, []byte("p3")); err != nil || ok {
		t.Fatalf("pending while active: %v %v", ok, err)
	}
}

func TestTOTPAttemptLocksOnThirdForTenMinutes(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	ctx := context.Background()
	u := seed(t, db, "totplock@example.com")
	now := time.Now()

	for i := 1; i <= 3; i++ {
		if ok, err := repo.TOTPAttempt(ctx, u.ID, now); err != nil || !ok {
			t.Fatal(i, ok, err)
		}
	}
	got := reload(t, db, u.ID)
	if got.TOTPFailures != 3 || got.TOTPLockedUntil == nil || got.TOTPLockedUntil.Sub(now.Add(10*time.Minute)).Abs() > time.Second {
		t.Fatalf("after 3: %d %v", got.TOTPFailures, got.TOTPLockedUntil)
	}
	if got.FailedAttempts != 0 {
		t.Fatalf("password counter touched: %d", got.FailedAttempts)
	}
	if ok, err := repo.TOTPAttempt(ctx, u.ID, now.Add(9*time.Minute)); err != nil || ok {
		t.Fatalf("4th while locked: %v %v", ok, err)
	}
	if ok, err := repo.TOTPAttempt(ctx, u.ID, now.Add(10*time.Minute)); err != nil || !ok {
		t.Fatalf("after expiry: %v %v", ok, err)
	}
	if got := reload(t, db, u.ID); got.TOTPFailures != 1 || got.TOTPLockedUntil != nil {
		t.Fatalf("restart: %d %v", got.TOTPFailures, got.TOTPLockedUntil)
	}
}

func TestTOTPAcceptRejectsReplayAndResets(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	ctx := context.Background()
	u := seed(t, db, "accept@example.com")

	repo.TOTPAttempt(ctx, u.ID, time.Now())
	repo.TOTPAttempt(ctx, u.ID, time.Now())
	if ok, err := repo.TOTPAccept(ctx, u.ID, 10); err != nil || !ok {
		t.Fatal(ok, err)
	}
	got := reload(t, db, u.ID)
	if got.TOTPLastCounter != 10 || got.TOTPFailures != 0 || got.TOTPLockedUntil != nil {
		t.Fatalf("accept: %+v", got)
	}
	for _, c := range []int64{10, 9} {
		if ok, err := repo.TOTPAccept(ctx, u.ID, c); err != nil || ok {
			t.Fatalf("replay %d: %v %v", c, ok, err)
		}
	}
}
