//go:build integration

package session_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/user"
	"gorm.io/gorm"
)

func seedUser(t *testing.T, db *gorm.DB, email string) *user.User {
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

func count(t *testing.T, db *gorm.DB, userID uint64) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&session.Session{}).Where("user_id = ?", userID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCreateStoresOnlyHash(t *testing.T) {
	db := database.TestTx(t)
	repo := session.NewRepository(db)
	ctx := context.Background()
	u := seedUser(t, db, "sess-create@example.com")
	now := time.Now()

	token, err := repo.Create(ctx, u.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Fatalf("token %q: %d bytes, %v", token, len(raw), err)
	}
	other, _ := repo.Create(ctx, u.ID, now)
	if other == token {
		t.Fatal("token not random")
	}
	var rows []session.Session
	if err := db.Where("user_id = ?", u.ID).Find(&rows).Error; err != nil || len(rows) != 2 {
		t.Fatalf("rows %d, %v", len(rows), err)
	}
	stored := map[[32]byte]bool{}
	for _, s := range rows {
		stored[[32]byte(s.TokenHash)] = true
		if bytes.Contains(s.TokenHash, raw) {
			t.Fatal("token stored in clear")
		}
	}
	if !stored[sha256.Sum256([]byte(token))] || !stored[sha256.Sum256([]byte(other))] {
		t.Fatal("stored hashes are not sha256 of the tokens")
	}
}

func TestTouchRenewsAndExpires(t *testing.T) {
	db := database.TestTx(t)
	repo := session.NewRepository(db)
	ctx := context.Background()
	u := seedUser(t, db, "sess-touch@example.com")
	t0 := time.Now().Truncate(time.Microsecond)

	token, err := repo.Create(ctx, u.ID, t0)
	if err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(29 * time.Minute)
	if id, ok, err := repo.Touch(ctx, token, t1); err != nil || !ok || id != u.ID {
		t.Fatalf("touch at 29m: %d %v %v", id, ok, err)
	}
	t2 := t1.Add(29 * time.Minute)
	if id, ok, err := repo.Touch(ctx, token, t2); err != nil || !ok || id != u.ID {
		t.Fatalf("renewed touch: %d %v %v", id, ok, err)
	}
	if _, ok, err := repo.Touch(ctx, token, t2.Add(session.IdleTimeout)); err != nil || ok {
		t.Fatalf("touch after 30m idle: %v %v", ok, err)
	}
	if _, ok, err := repo.Touch(ctx, "nope", t2); err != nil || ok {
		t.Fatalf("unknown token: %v %v", ok, err)
	}
	if session.IdleTimeout != 30*time.Minute {
		t.Fatal("idle timeout differs from spec")
	}
}

func TestDeleteInvalidatesToken(t *testing.T) {
	db := database.TestTx(t)
	repo := session.NewRepository(db)
	ctx := context.Background()
	u := seedUser(t, db, "sess-delete@example.com")
	now := time.Now()

	token, _ := repo.Create(ctx, u.ID, now)
	keep, _ := repo.Create(ctx, u.ID, now)
	if err := repo.Delete(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := repo.Touch(ctx, token, now); err != nil || ok {
		t.Fatalf("touch after delete: %v %v", ok, err)
	}
	if _, ok, _ := repo.Touch(ctx, keep, now); !ok {
		t.Fatal("other session deleted")
	}
}

func TestPurgeExpiredOnlyExpired(t *testing.T) {
	db := database.TestTx(t)
	repo := session.NewRepository(db)
	ctx := context.Background()
	u := seedUser(t, db, "sess-purge@example.com")
	now := time.Now().Truncate(time.Microsecond)

	old, _ := repo.Create(ctx, u.ID, now.Add(-31*time.Minute))
	fresh, _ := repo.Create(ctx, u.ID, now.Add(-29*time.Minute))
	if err := repo.PurgeExpired(ctx, now); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, u.ID); n != 1 {
		t.Fatalf("%d sessions left, want 1", n)
	}
	if _, ok, _ := repo.Touch(ctx, fresh, now); !ok {
		t.Fatal("fresh session purged")
	}
	if _, ok, _ := repo.Touch(ctx, old, now.Add(-31*time.Minute)); ok {
		t.Fatal("expired session survived purge")
	}
}

func TestSessionsCascadeOnUserDelete(t *testing.T) {
	db := database.TestTx(t)
	repo := session.NewRepository(db)
	ctx := context.Background()
	u := seedUser(t, db, "sess-cascade@example.com")
	if _, err := repo.Create(ctx, u.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&user.User{}, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, u.ID); n != 0 {
		t.Fatalf("%d sessions after user delete", n)
	}
}
