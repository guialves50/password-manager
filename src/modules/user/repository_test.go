//go:build integration

package user_test

import (
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

func TestRecordFailureLocksOnFifth(t *testing.T) {
	db := database.TestTx(t)
	repo := user.NewRepository(db)
	ctx := context.Background()
	u := seed(t, db, "lock@example.com")

	for i := 1; i <= 4; i++ {
		if err := repo.RecordFailure(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	got := reload(t, db, u.ID)
	if got.FailedAttempts != 4 || got.LockedUntil != nil {
		t.Fatalf("after 4: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}

	before := time.Now()
	if err := repo.RecordFailure(ctx, u.ID); err != nil {
		t.Fatal(err)
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
	}
	if err := db.Create(u).Error; err == nil {
		t.Fatal("uppercase email accepted")
	}
}
