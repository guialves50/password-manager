//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/database"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	"github.com/guialves50/password-manager/src/modules/auth/login/services"
	"github.com/guialves50/password-manager/src/modules/auth/totp"
	"github.com/guialves50/password-manager/src/server"
)

// Without PM_SERVER_SECRET the server's key dies with the process, so 2FA
// can't be turned on at all.
func TestTOTPUnavailableWithEphemeralSecret(t *testing.T) {
	db := database.TestTx(t)
	srv := httptest.NewServer(server.New(db, server.Config{Secret: bytes.Repeat([]byte{1}, 32), AuthParams: keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}, Ephemeral: true}))
	defer srv.Close()
	t.Setenv("PM_SERVER", srv.URL)
	email := fmt.Sprintf("ephemeral+%d@test.local", time.Now().UnixNano())
	p, _ := fakePrompter(email+"\n", "SenhaForte1", "SenhaForte1")
	if code := start([]string{"register"}, p, io.Discard); code != 0 {
		t.Fatalf("register: %d", code)
	}
	c, _ := api.New(srv.URL)
	s, err := (&services.Service{API: c}).Login(context.Background(), dto.Input{Email: email, Password: []byte("SenhaForte1")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Setup2FA(context.Background(), s); !errors.Is(err, autherrors.ErrTOTPUnavailable) {
		t.Fatalf("setup: %v", err)
	}
	var pending bool
	if err := db.Raw("SELECT totp_pending IS NOT NULL FROM users WHERE email = ?", email).Scan(&pending).Error; err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("pending secret stored without a stable key")
	}
}

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
	if err := db.Raw("SELECT totp_secret FROM users WHERE email = ?", email).Row().Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 20+12+16 || bytes.Contains(stored, secret) {
		t.Fatalf("stored secret %x", stored)
	}

	err = login(b, codeAt(1))
	if !errors.Is(err, autherrors.ErrTOTPUnreadable) {
		t.Fatalf("other server secret: %v", err)
	}
	var failures int
	db.Raw("SELECT totp_failures FROM users WHERE email = ?", email).Scan(&failures)
	if failures != 0 {
		t.Fatalf("unreadable secret counted as a failure: %d", failures)
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
