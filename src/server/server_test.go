//go:build integration

package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	logindto "github.com/guialves50/password-manager/src/modules/auth/login/dto"
	prelogindto "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	recoverdto "github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	registerdto "github.com/guialves50/password-manager/src/modules/auth/register/dto"
	"github.com/guialves50/password-manager/src/modules/session"
	itemsdto "github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/server"
)

var cheap = keys.Params{Time: 1, MemoryKiB: 1024, Threads: 1}

type client struct {
	t   *testing.T
	url string
}

func (c client) do(method, path, token string, body any) (int, []byte) {
	c.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, c.url+path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func (c client) expectError(method, path, token string, body any, status int, code string) {
	c.t.Helper()
	got, out := c.do(method, path, token, body)
	var e struct{ Error string }
	json.Unmarshal(out, &e)
	if got != status || e.Error != code {
		c.t.Fatalf("%s %s: %d %q, want %d %q", method, path, got, out, status, code)
	}
}

type account struct {
	email                  string
	password, recoveryKey  []byte
	masterSalt, recSalt    []byte
	vaultKey               []byte
	authHash, recoveryHash []byte
}

func split(t *testing.T, secret, salt []byte) (auth, enc []byte) {
	t.Helper()
	auth, enc, err := keys.Split(keys.Derive(secret, salt, cheap))
	if err != nil {
		t.Fatal(err)
	}
	return auth, enc
}

func register(t *testing.T, c client, email string) account {
	t.Helper()
	a := account{email: email, password: []byte("senha mestra " + email), recoveryKey: []byte("recovery " + email)}
	a.masterSalt, _ = keys.Random(16)
	a.recSalt, _ = keys.Random(16)
	a.vaultKey, _ = keys.Random(32)
	var enc, recEnc []byte
	a.authHash, enc = split(t, a.password, a.masterSalt)
	a.recoveryHash, recEnc = split(t, a.recoveryKey, a.recSalt)
	masterBlob, err := keys.Seal(enc, a.vaultKey, []byte("pm/master/v1|"+email))
	if err != nil {
		t.Fatal(err)
	}
	recoveryBlob, err := keys.Seal(recEnc, a.vaultKey, []byte("pm/recovery/v1|"+email))
	if err != nil {
		t.Fatal(err)
	}
	status, out := c.do("POST", "/register", "", registerdto.Request{
		Email: email, KDF: prelogindto.KDF{Time: cheap.Time, MemoryKiB: cheap.MemoryKiB, Threads: cheap.Threads},
		MasterSalt: a.masterSalt, MasterBlob: masterBlob, AuthHash: a.authHash,
		RecoverySalt: a.recSalt, RecoveryBlob: recoveryBlob, RecoveryAuthHash: a.recoveryHash,
	})
	if status != http.StatusCreated {
		t.Fatalf("register %s: %d %q", email, status, out)
	}
	return a
}

func login(t *testing.T, c client, a account) string {
	t.Helper()
	status, out := c.do("POST", "/prelogin", "", prelogindto.Request{Email: a.email})
	var pre prelogindto.Response
	if status != http.StatusOK || json.Unmarshal(out, &pre) != nil {
		t.Fatalf("prelogin: %d %q", status, out)
	}
	if !bytes.Equal(pre.MasterSalt, a.masterSalt) || !bytes.Equal(pre.RecoverySalt, a.recSalt) ||
		pre.KDF != (prelogindto.KDF{Time: cheap.Time, MemoryKiB: cheap.MemoryKiB, Threads: cheap.Threads}) {
		t.Fatalf("prelogin %+v", pre)
	}
	auth, enc := split(t, a.password, pre.MasterSalt)
	status, out = c.do("POST", "/login", "", logindto.Request{Email: a.email, AuthHash: auth})
	var res logindto.Response
	if status != http.StatusOK || json.Unmarshal(out, &res) != nil || res.Token == "" || res.UserID == 0 {
		t.Fatalf("login: %d %q", status, out)
	}
	vaultKey, err := keys.Open(enc, res.MasterBlob, []byte("pm/master/v1|"+a.email))
	if err != nil || !bytes.Equal(vaultKey, a.vaultKey) {
		t.Fatalf("master blob does not open to vault key: %v", err)
	}
	return res.Token
}

func listItems(t *testing.T, c client, token string) []itemsdto.StoredItem {
	t.Helper()
	status, out := c.do("GET", "/items", token, nil)
	var items []itemsdto.StoredItem
	if status != http.StatusOK || json.Unmarshal(out, &items) != nil {
		t.Fatalf("list: %d %q", status, out)
	}
	return items
}

func TestServerEndToEnd(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	srv := httptest.NewServer(server.New(database.TestTx(t), server.Config{Secret: bytes.Repeat([]byte{7}, 32), AuthParams: cheap, Now: now}))
	defer srv.Close()
	c := client{t: t, url: srv.URL}

	alice := register(t, c, "alice-server@example.com")
	bob := register(t, c, "bob-server@example.com")
	aliceToken := login(t, c, alice)
	bobToken := login(t, c, bob)

	c.expectError("POST", "/login", "", logindto.Request{Email: alice.email, AuthHash: bob.authHash}, http.StatusUnauthorized, "invalid_credentials")

	status, out := c.do("POST", "/recover/start", "", recoverdto.StartRequest{Email: alice.email, RecoveryAuthHash: alice.recoveryHash})
	var start recoverdto.StartResponse
	if status != http.StatusOK || json.Unmarshal(out, &start) != nil || len(start.RecoveryBlob) != 60 {
		t.Fatalf("recover/start: %d %q", status, out)
	}
	c.expectError("POST", "/recover/finish", "", recoverdto.FinishRequest{
		Email: bob.email, RecoveryAuthHash: alice.recoveryHash,
		MasterSalt: alice.masterSalt, MasterBlob: start.RecoveryBlob, AuthHash: alice.authHash,
		RecoverySalt: alice.recSalt, RecoveryBlob: start.RecoveryBlob, NewRecoveryAuthHash: alice.recoveryHash,
	}, http.StatusUnauthorized, "invalid_recovery")

	itemID := strings.Repeat("ab", 16)
	if status, out := c.do("POST", "/items", aliceToken, map[string]any{"id": itemID, "blob": []byte("cifrado"), "user_id": 999}); status != http.StatusCreated {
		t.Fatalf("create: %d %q", status, out)
	}
	if items := listItems(t, c, aliceToken); len(items) != 1 || items[0].ID != itemID || string(items[0].Blob) != "cifrado" {
		t.Fatalf("alice items %+v", items)
	}
	c.expectError("POST", "/items", aliceToken, itemsdto.StoredItem{ID: "nope", Blob: []byte("x")}, http.StatusBadRequest, "invalid_request")

	if items := listItems(t, c, bobToken); len(items) != 0 {
		t.Fatalf("bob sees %+v", items)
	}
	c.expectError("DELETE", "/items/"+itemID, bobToken, nil, http.StatusNotFound, "not_found")
	if items := listItems(t, c, aliceToken); len(items) != 1 {
		t.Fatalf("bob deleted alice's item: %+v", items)
	}

	for _, r := range []struct{ method, path string }{{"GET", "/items"}, {"POST", "/items"}, {"DELETE", "/items/" + itemID}, {"POST", "/logout"}} {
		c.expectError(r.method, r.path, "", nil, http.StatusUnauthorized, "unauthorized")
		c.expectError(r.method, r.path, "forged", nil, http.StatusUnauthorized, "unauthorized")
	}

	c.expectError("POST", "/items", aliceToken, bytes.Repeat([]byte("a"), 65<<10), http.StatusRequestEntityTooLarge, "too_large")
	c.expectError("POST", "/register", "", bytes.Repeat([]byte("a"), 65<<10), http.StatusRequestEntityTooLarge, "too_large")

	if status, out := c.do("DELETE", "/items/"+itemID, aliceToken, nil); status != http.StatusNoContent {
		t.Fatalf("delete: %d %q", status, out)
	}
	if items := listItems(t, c, aliceToken); len(items) != 0 {
		t.Fatalf("not deleted: %+v", items)
	}

	if status, out := c.do("POST", "/logout", aliceToken, nil); status != http.StatusNoContent {
		t.Fatalf("logout: %d %q", status, out)
	}
	c.expectError("GET", "/items", aliceToken, nil, http.StatusUnauthorized, "unauthorized")

	clock.Add(int64(session.IdleTimeout - time.Second))
	listItems(t, c, bobToken)
	clock.Add(int64(session.IdleTimeout - time.Second))
	listItems(t, c, bobToken)
	clock.Add(int64(session.IdleTimeout + time.Second))
	c.expectError("GET", "/items", bobToken, nil, http.StatusUnauthorized, "unauthorized")
}

func TestServerNilNowDefaultsToWallClock(t *testing.T) {
	srv := httptest.NewServer(server.New(database.TestTx(t), server.Config{Secret: bytes.Repeat([]byte{7}, 32), AuthParams: cheap}))
	defer srv.Close()
	c := client{t: t, url: srv.URL}
	token := login(t, c, register(t, c, "clock-server@example.com"))
	listItems(t, c, token)
}
