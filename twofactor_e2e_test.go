//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	"github.com/guialves50/password-manager/src/modules/auth/login/services"
	"github.com/guialves50/password-manager/src/modules/auth/totp"
	"github.com/guialves50/password-manager/src/server"
)

// TFA-01 AC8 + edge case: the TOTP secret is sealed under a key derived from
// PM_SERVER_SECRET, so a server with another secret answers 500 and opens no session.
func TestTOTPSecretBoundToServerSecret(t *testing.T) {
	db := database.TestTx(t)
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	params := keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	newServer := func(secret byte) (*httptest.Server, *api.Client) {
		srv := httptest.NewServer(server.New(db, server.Config{Secret: bytes.Repeat([]byte{secret}, 32), AuthParams: params, Now: now}))
		t.Cleanup(srv.Close)
		c, err := api.New(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		return srv, c
	}
	srvA, a := newServer(1)
	_, b := newServer(2)
	t.Setenv("PM_SERVER", srvA.URL)
	email := fmt.Sprintf("totp+%d@test.local", time.Now().UnixNano())
	p, _ := fakePrompter(email+"\n", "SenhaForte1", "SenhaForte1")
	if code := start([]string{"register"}, p, io.Discard); code != 0 {
		t.Fatalf("register: %d", code)
	}

	ctx := context.Background()
	login := func(c *api.Client, code string) error {
		_, err := (&services.Service{API: c}).Login(ctx, dto.Input{Email: email, Password: []byte("SenhaForte1"), Code: func() (string, error) { return code, nil }})
		return err
	}
	s, err := (&services.Service{API: a}).Login(ctx, dto.Input{Email: email, Password: []byte("SenhaForte1")})
	if err != nil {
		t.Fatal(err)
	}
	setup, err := a.Setup2FA(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	codeAt := func(step int64) string { return totp.Code(secret, uint64(clock.Unix()/totp.Step+step), totp.Digits) }
	if err := a.Confirm2FA(ctx, s, codeAt(0)); err != nil {
		t.Fatal(err)
	}

	var stored []byte
	db.Raw("SELECT totp_secret FROM users WHERE email = ?", email).Scan(&stored)
	if len(stored) == 0 || bytes.Contains(stored, secret) {
		t.Fatalf("stored secret %x", stored)
	}

	err = login(b, codeAt(1))
	if err == nil || !strings.Contains(err.Error(), "status 500") || !strings.Contains(err.Error(), `"internal"`) {
		t.Fatalf("other server secret: %v", err)
	}
	var sessions int64
	db.Raw("SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = ?", email).Scan(&sessions)
	if sessions != 1 {
		t.Fatalf("sessions after failed login: %d", sessions)
	}
	if err := login(a, codeAt(1)); err != nil {
		t.Fatalf("same server secret: %v", err)
	}
}
