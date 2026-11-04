//go:build integration

package repository_test

import (
	"context"
	"errors"
	"testing"

	"github.com/guialves50/password-manager/src/database"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/register/repository"
	"github.com/guialves50/password-manager/src/modules/user"
)

func newUser(email string) *user.User {
	return &user.User{
		Email: email, KDFTime: 3, KDFMemoryKiB: 65536, KDFThreads: 4,
		MasterSalt: []byte("s"), MasterWrappedKey: []byte("m"),
		RecoverySalt: []byte("r"), RecoveryWrappedKey: []byte("k"),
		AuthSalt: []byte("as"), AuthHash: []byte("ah"),
		RecoveryAuthSalt: []byte("ras"), RecoveryAuthHash: []byte("rah"),
	}
}

func TestCreatePersistsAndRejectsDuplicate(t *testing.T) {
	db := database.TestTx(t)
	repo := repository.New(db)
	ctx := context.Background()

	u := newUser("create@example.com")
	if err := repo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	var got user.User
	if err := db.First(&got, u.ID).Error; err != nil || got.Email != "create@example.com" || string(got.MasterWrappedKey) != "m" {
		t.Fatalf("got %+v, %v", got, err)
	}

	if err := repo.Create(ctx, newUser("create@example.com")); !errors.Is(err, autherrors.ErrEmailTaken) {
		t.Fatalf("want ErrEmailTaken, got %v", err)
	}
}
