package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	login "github.com/guialves50/password-manager/src/modules/auth/login/dto"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	recovery "github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	register "github.com/guialves50/password-manager/src/modules/auth/register/dto"
)

type captured struct {
	method, path, auth string
	body               map[string]any
}

func fakeServer(t *testing.T, status int, resp string) (*Client, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			if err := json.Unmarshal(b, &got.body); err != nil {
				t.Errorf("body %q: %v", b, err)
			}
		}
		w.WriteHeader(status)
		w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c, got
}

func b64(b []byte) string {
	out, _ := json.Marshal(b)
	return string(out[1 : len(out)-1])
}

func expect(t *testing.T, got *captured, method, path, auth string, body map[string]any) {
	t.Helper()
	if got.method != method || got.path != path || got.auth != auth {
		t.Fatalf("%s %s auth %q", got.method, got.path, got.auth)
	}
	want, _ := json.Marshal(body)
	have, _ := json.Marshal(got.body)
	if !bytes.Equal(want, have) {
		t.Fatalf("body %s, want %s", have, want)
	}
}

var (
	s16 = bytes.Repeat([]byte{1}, 16)
	r16 = bytes.Repeat([]byte{2}, 16)
	h32 = bytes.Repeat([]byte{3}, 32)
	b60 = bytes.Repeat([]byte{4}, 60)
)

func TestPrelogin(t *testing.T) {
	resp := `{"kdf":{"time":3,"memory_kib":65536,"threads":4},"master_salt":"` + b64(s16) + `","recovery_salt":"` + b64(r16) + `"}`
	c, got := fakeServer(t, 200, resp)
	out, err := c.Prelogin(context.Background(), "a@b.com")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/prelogin", "", map[string]any{"email": "a@b.com"})
	if out.KDF != (prelogin.KDF{Time: 3, MemoryKiB: 65536, Threads: 4}) || !bytes.Equal(out.MasterSalt, s16) || !bytes.Equal(out.RecoverySalt, r16) {
		t.Fatalf("out %+v", out)
	}
}

func TestPreloginRejectsUnusableResponse(t *testing.T) {
	salts := `,"master_salt":"` + b64(s16) + `","recovery_salt":"` + b64(r16) + `"}`
	for _, resp := range []string{
		`{"kdf":{"time":0,"memory_kib":65536,"threads":4}` + salts,
		`{"kdf":{"time":3,"memory_kib":0,"threads":4}` + salts,
		`{"kdf":{"time":3,"memory_kib":65536,"threads":0}` + salts,
		`{"kdf":{"time":2,"memory_kib":65536,"threads":4}` + salts,
		`{"kdf":{"time":3,"memory_kib":65535,"threads":4}` + salts,
		`{"kdf":{"time":1,"memory_kib":8192,"threads":1}` + salts,
		`{"kdf":{"time":31,"memory_kib":65536,"threads":4}` + salts,
		`{"kdf":{"time":3,"memory_kib":1048577,"threads":4}` + salts,
		`{"kdf":{"time":3,"memory_kib":65536,"threads":4},"master_salt":"","recovery_salt":"` + b64(r16) + `"}`,
		`{"kdf":{"time":3,"memory_kib":65536,"threads":4},"master_salt":"` + b64(s16) + `"}`,
	} {
		c, _ := fakeServer(t, 200, resp)
		if _, err := c.Prelogin(context.Background(), "a@b.com"); err == nil || autherrors.Message(err) != "erro interno" {
			t.Errorf("%s: got %v", resp, err)
		}
	}
}

func TestRegister(t *testing.T) {
	c, got := fakeServer(t, 201, "")
	req := register.Request{Email: "a@b.com", KDF: prelogin.KDF{Time: 3, MemoryKiB: 65536, Threads: 4}, MasterSalt: s16, MasterBlob: b60, AuthHash: h32, RecoverySalt: r16, RecoveryBlob: b60, RecoveryAuthHash: h32}
	if err := c.Register(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/register", "", map[string]any{
		"email": "a@b.com", "kdf": map[string]any{"time": 3, "memory_kib": 65536, "threads": 4},
		"master_salt": b64(s16), "master_blob": b64(b60), "auth_hash": b64(h32),
		"recovery_salt": b64(r16), "recovery_blob": b64(b60), "recovery_auth_hash": b64(h32),
	})
	c, _ = fakeServer(t, 409, `{"error":"email_taken"}`)
	if err := c.Register(context.Background(), req); !errors.Is(err, autherrors.ErrEmailTaken) {
		t.Fatalf("got %v", err)
	}
}

func TestLogin(t *testing.T) {
	c, got := fakeServer(t, 200, `{"token":"tok","user_id":42,"master_blob":"`+b64(b60)+`"}`)
	out, err := c.Login(context.Background(), login.Request{Email: "a@b.com", AuthHash: h32})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/login", "", map[string]any{"email": "a@b.com", "auth_hash": b64(h32)})
	if out.Token != "tok" || out.UserID != 42 || !bytes.Equal(out.MasterBlob, b60) {
		t.Fatalf("out %+v", out)
	}
	c, _ = fakeServer(t, 401, `{"error":"invalid_credentials"}`)
	if _, err := c.Login(context.Background(), login.Request{Email: "a@b.com", AuthHash: h32}); !errors.Is(err, autherrors.ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
}

func TestLogout(t *testing.T) {
	c, got := fakeServer(t, 204, "")
	if err := c.Logout(context.Background(), "tok"); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/logout", "Bearer tok", nil)
}

func TestRecoverStart(t *testing.T) {
	c, got := fakeServer(t, 200, `{"recovery_blob":"`+b64(b60)+`"}`)
	out, err := c.RecoverStart(context.Background(), recovery.StartRequest{Email: "a@b.com", RecoveryAuthHash: h32})
	if err != nil || !bytes.Equal(out.RecoveryBlob, b60) {
		t.Fatalf("out %+v err %v", out, err)
	}
	expect(t, got, "POST", "/recover/start", "", map[string]any{"email": "a@b.com", "recovery_auth_hash": b64(h32)})
	c, _ = fakeServer(t, 401, `{"error":"invalid_recovery"}`)
	if _, err := c.RecoverStart(context.Background(), recovery.StartRequest{Email: "a@b.com", RecoveryAuthHash: h32}); !errors.Is(err, autherrors.ErrInvalidRecovery) {
		t.Fatalf("got %v", err)
	}
}

func TestRecoverFinish(t *testing.T) {
	c, got := fakeServer(t, 204, "")
	h2 := bytes.Repeat([]byte{5}, 32)
	req := recovery.FinishRequest{Email: "a@b.com", RecoveryAuthHash: h32, MasterSalt: s16, MasterBlob: b60, AuthHash: h2, RecoverySalt: r16, RecoveryBlob: b60, NewRecoveryAuthHash: h2}
	if err := c.RecoverFinish(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/recover/finish", "", map[string]any{
		"email": "a@b.com", "recovery_auth_hash": b64(h32), "master_salt": b64(s16), "master_blob": b64(b60),
		"auth_hash": b64(h2), "recovery_salt": b64(r16), "recovery_blob": b64(b60), "new_recovery_auth_hash": b64(h2),
	})
}
