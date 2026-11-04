//go:build integration

package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/auth/recover/repository"
	"github.com/guialves50/password-manager/src/modules/user"
	"gorm.io/gorm"
)

func TestRotateKeysReplacesKeysAndResetsLockout(t *testing.T) {
	db := database.TestTx(t)
	ctx := context.Background()
	until := time.Now().Add(10 * time.Minute)
	u := &user.User{
		Email: "rotate@example.com", KDFTime: 3, KDFMemoryKiB: 65536, KDFThreads: 4,
		MasterSalt: []byte("s"), MasterWrappedKey: []byte("m"),
		RecoverySalt: []byte("r"), RecoveryWrappedKey: []byte("k"),
		FailedAttempts: 5, LockedUntil: &until,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}

	if err := repository.New(db).RotateKeys(ctx, u.ID, []byte("s2"), []byte("m2"), []byte("r2"), []byte("k2")); err != nil {
		t.Fatal(err)
	}
	var got user.User
	if err := db.First(&got, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if string(got.MasterSalt) != "s2" || string(got.MasterWrappedKey) != "m2" || string(got.RecoverySalt) != "r2" || string(got.RecoveryWrappedKey) != "k2" {
		t.Fatalf("keys not rotated: %q %q %q %q", got.MasterSalt, got.MasterWrappedKey, got.RecoverySalt, got.RecoveryWrappedKey)
	}
	if got.FailedAttempts != 0 || got.LockedUntil != nil {
		t.Fatalf("lockout not reset: attempts=%d locked=%v", got.FailedAttempts, got.LockedUntil)
	}
	if got.Email != "rotate@example.com" || got.KDFTime != 3 {
		t.Fatalf("unrelated fields changed: %+v", got)
	}
}

func TestRotateKeysMissingUser(t *testing.T) {
	db := database.TestTx(t)
	err := repository.New(db).RotateKeys(context.Background(), 0, []byte("s"), []byte("m"), []byte("r"), []byte("k"))
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("got %v", err)
	}
}
