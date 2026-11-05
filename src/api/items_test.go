package api

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
)

func TestListItems(t *testing.T) {
	c, got := fakeServer(t, 200, `[{"id":"aa","blob":"`+b64(b60)+`"},{"id":"bb","blob":"`+b64(s16)+`"}]`)
	items, err := c.ListItems(context.Background(), &cli.Session{UserID: 9, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, got, "GET", "/items", "Bearer tok", nil)
	if len(items) != 2 || items[0].ID != "aa" || !bytes.Equal(items[0].Blob, b60) || items[1].ID != "bb" || !bytes.Equal(items[1].Blob, s16) {
		t.Fatalf("items %+v", items)
	}
	c, _ = fakeServer(t, 401, `{"error":"unauthorized"}`)
	if _, err := c.ListItems(context.Background(), &cli.Session{Token: "old"}); !errors.Is(err, autherrors.ErrSessionExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestCreateItemSendsOnlyIDAndBlob(t *testing.T) {
	c, got := fakeServer(t, 201, "")
	if err := c.CreateItem(context.Background(), &cli.Session{UserID: 9, Email: "a@b.com", VaultKey: h32, Token: "tok"}, "abc", b60); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/items", "Bearer tok", map[string]any{"id": "abc", "blob": b64(b60)})
}

func TestDeleteItem(t *testing.T) {
	c, got := fakeServer(t, 204, "")
	ok, err := c.DeleteItem(context.Background(), &cli.Session{Token: "tok"}, "abc")
	if !ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
	expect(t, got, "DELETE", "/items/abc", "Bearer tok", nil)

	c, _ = fakeServer(t, 404, `{"error":"not_found"}`)
	if ok, err := c.DeleteItem(context.Background(), &cli.Session{Token: "tok"}, "abc"); ok || err != nil {
		t.Fatalf("not found: ok %v err %v", ok, err)
	}
	c, _ = fakeServer(t, 401, `{"error":"unauthorized"}`)
	if ok, err := c.DeleteItem(context.Background(), &cli.Session{Token: "tok"}, "abc"); ok || !errors.Is(err, autherrors.ErrSessionExpired) {
		t.Fatalf("expired: ok %v err %v", ok, err)
	}
}
