//go:build integration

package router_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/user"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
	"github.com/guialves50/password-manager/src/modules/vault/items/router"
	"github.com/guialves50/password-manager/src/server"
)

func TestDeleteDuplicateRemovesOldest(t *testing.T) {
	tx := database.TestTx(t)
	u := user.User{Email: "dup@example.com", MasterSalt: []byte{1}, MasterWrappedKey: []byte{1}, RecoverySalt: []byte{1}, RecoveryWrappedKey: []byte{1},
		AuthSalt: []byte{1}, AuthHash: []byte{1}, RecoveryAuthSalt: []byte{1}, RecoveryAuthHash: []byte{1}}
	if err := tx.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	vk, err := keys.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i, id := range []string{strings.Repeat("b", 32), strings.Repeat("a", 32)} {
		blob, err := keys.Seal(vk, []byte(`{"name":"gmail","password":"p"}`), fmt.Appendf(nil, "pm/item/v1|%d|%s", u.ID, id))
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Create(&repository.Item{ID: id, UserID: u.ID, Blob: blob, CreatedAt: base.Add(time.Duration(i) * time.Minute)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("s\n")), Out: &out}
	token, err := session.NewRepository(tx).Create(context.Background(), u.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.New(tx, server.Config{Secret: make([]byte, 32), AuthParams: keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}}))
	defer srv.Close()
	c, err := api.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := &cli.Session{UserID: u.ID, VaultKey: vk, Token: token}

	if err := router.Routes(c)["delete"](context.Background(), p, s, "GMAIL"); err != nil {
		t.Fatal(err)
	}
	var left []repository.Item
	if err := tx.Where("user_id = ?", u.ID).Find(&left).Error; err != nil {
		t.Fatal(err)
	}
	if out.String() != "remover gmail? (s/N) item removido\n" || len(left) != 1 || left[0].ID != strings.Repeat("a", 32) {
		t.Fatalf("out %q left %+v", out.String(), left)
	}
}
