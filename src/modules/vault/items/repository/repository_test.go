//go:build integration

package repository_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
	"gorm.io/gorm"
)

func seedUser(t *testing.T, db *gorm.DB, email string) *user.User {
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

func id(c string) string {
	return strings.Repeat(c, 32)
}

func ids(items []repository.Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ID
	}
	return out
}

func TestCreateAndListByUserScopedAndOrdered(t *testing.T) {
	db := database.TestTx(t)
	repo := repository.New(db)
	ctx := context.Background()
	alice := seedUser(t, db, "alice-items@example.com")
	bob := seedUser(t, db, "bob-items@example.com")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Microsecond)

	for _, it := range []repository.Item{
		{ID: id("c"), UserID: alice.ID, Blob: []byte("blob-c"), CreatedAt: t0.Add(2 * time.Second)},
		{ID: id("b"), UserID: alice.ID, Blob: []byte("blob-b"), CreatedAt: t0},
		{ID: id("a"), UserID: alice.ID, Blob: []byte("blob-a"), CreatedAt: t0.Add(time.Second)},
		{ID: id("0"), UserID: alice.ID, Blob: []byte("blob-0"), CreatedAt: t0.Add(time.Second)},
		{ID: id("d"), UserID: bob.ID, Blob: []byte("blob-d"), CreatedAt: t0.Add(-time.Second)},
	} {
		if err := repo.Create(ctx, &it); err != nil {
			t.Fatal(err)
		}
	}

	got, err := repo.ListByUser(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{id("b"), id("0"), id("a"), id("c")}; strings.Join(ids(got), ",") != strings.Join(want, ",") {
		t.Fatalf("order %v, want %v", ids(got), want)
	}
	for _, it := range got {
		if it.UserID != alice.ID || string(it.Blob) != "blob-"+it.ID[:1] {
			t.Fatalf("item %+v", it)
		}
	}
	got, err = repo.ListByUser(ctx, bob.ID)
	if err != nil || len(got) != 1 || got[0].ID != id("d") {
		t.Fatalf("bob: %v, %v", ids(got), err)
	}
}

func TestDeleteScopedToUser(t *testing.T) {
	db := database.TestTx(t)
	repo := repository.New(db)
	ctx := context.Background()
	alice := seedUser(t, db, "alice-del@example.com")
	bob := seedUser(t, db, "bob-del@example.com")
	if err := repo.Create(ctx, &repository.Item{ID: id("a"), UserID: alice.ID, Blob: []byte("x")}); err != nil {
		t.Fatal(err)
	}

	ok, err := repo.Delete(ctx, bob.ID, id("a"))
	if err != nil || ok {
		t.Fatalf("other user: %v, %v", ok, err)
	}
	if got, _ := repo.ListByUser(ctx, alice.ID); len(got) != 1 {
		t.Fatalf("item removed by other user: %v", ids(got))
	}

	ok, err = repo.Delete(ctx, alice.ID, id("a"))
	if err != nil || !ok {
		t.Fatalf("owner: %v, %v", ok, err)
	}
	if got, _ := repo.ListByUser(ctx, alice.ID); len(got) != 0 {
		t.Fatalf("item not removed: %v", ids(got))
	}
	ok, err = repo.Delete(ctx, alice.ID, id("a"))
	if err != nil || ok {
		t.Fatalf("missing: %v, %v", ok, err)
	}
}

func TestDeletingUserCascadesItems(t *testing.T) {
	db := database.TestTx(t)
	repo := repository.New(db)
	ctx := context.Background()
	u := seedUser(t, db, "cascade@example.com")
	if err := repo.Create(ctx, &repository.Item{ID: id("e"), UserID: u.ID, Blob: []byte("x")}); err != nil {
		t.Fatal(err)
	}

	if err := db.Delete(&user.User{}, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := db.Model(&repository.Item{}).Where("id = ?", id("e")).Count(&n).Error; err != nil || n != 0 {
		t.Fatalf("items left %d, %v", n, err)
	}
}
