package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
)

func TestNewTransportGuard(t *testing.T) {
	ok := []string{"https://exemplo.com", "https://exemplo.com:8443/pm/", "http://localhost:8080", "http://127.0.0.1:8080", "http://127.9.8.7", "http://[::1]:8080"}
	for _, u := range ok {
		if c, err := New(u); err != nil || c == nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := []string{"http://exemplo.com", "http://10.0.0.1:8080", "http://localhost.exemplo.com", "http://[::2]", "ftp://127.0.0.1", "127.0.0.1:8080", "", "://x"}
	for _, u := range bad {
		if c, err := New(u); !errors.Is(err, autherrors.ErrInsecureServer) || c != nil {
			t.Errorf("%s: got %v, %v", u, c, err)
		}
	}
}

func TestDoUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.do(context.Background(), "GET", "/items", "", nil, nil); !errors.Is(err, autherrors.ErrUnreachable) {
		t.Fatalf("got %v", err)
	}
	if autherrors.Message(c.do(context.Background(), "GET", "/items", "", nil, nil)) != "não foi possível conectar ao servidor" {
		t.Fatal("message")
	}
}

func TestDoTimeout(t *testing.T) {
	c, _ := New("http://127.0.0.1")
	if c.http.Timeout.Seconds() != 30 {
		t.Fatalf("timeout %v", c.http.Timeout)
	}
}

func TestDoSendsJSONAndBearer(t *testing.T) {
	var gotAuth, gotType, gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotType, gotMethod, gotPath = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Method, r.URL.Path
		w.Write([]byte(`{"x":"ok"}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL + "/")
	var out struct{ X string }
	if err := c.do(context.Background(), "POST", "/login", "tok", map[string]string{"a": "b"}, &out); err != nil || out.X != "ok" {
		t.Fatalf("out %+v err %v", out, err)
	}
	if gotAuth != "Bearer tok" || gotType != "application/json" || gotMethod != "POST" || gotPath != "/login" {
		t.Fatalf("auth %q type %q method %q path %q", gotAuth, gotType, gotMethod, gotPath)
	}
	if err := c.do(context.Background(), "GET", "/items", "", nil, nil); err != nil || gotAuth != "" {
		t.Fatalf("no token: auth %q err %v", gotAuth, err)
	}
}

func TestDoMapsErrorCodes(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{409, `{"error":"email_taken"}`, "email já cadastrado"},
		{401, `{"error":"invalid_credentials"}`, "email ou senha mestra inválidos"},
		{401, `{"error":"invalid_recovery"}`, "email ou chave de recuperação inválidos"},
		{401, `{"error":"unauthorized"}`, "sessão expirada, faça login novamente"},
		{423, `{"error":"locked","minutes":7}`, "conta bloqueada, tente novamente em 7 minutos"},
		{401, `{"error":"totp_required"}`, "código 2FA necessário"},
		{401, `{"error":"invalid_totp"}`, "código 2FA inválido"},
		{409, `{"error":"totp_enabled"}`, "2FA já está ativo"},
		{409, `{"error":"no_pending"}`, "rode 2fa novamente"},
		{500, `{"error":"invalid_totp"}`, "erro interno"},
		{404, `{"error":"not_found"}`, "item não encontrado"},
		{400, `{"error":"invalid_request"}`, "erro interno"},
		{413, `{"error":"too_large"}`, "erro interno"},
		{500, `{"error":"internal"}`, "erro interno"},
		{500, `{"error":"invalid_credentials"}`, "erro interno"},
		{502, `bad gateway`, "erro interno"},
		{418, `{"error":"teapot"}`, "erro interno"},
		{423, `{"error":"locked"}`, "erro interno"},
		{503, `{"error":"busy"}`, "servidor ocupado, tente novamente em instantes"},
		{503, `{"error":"internal"}`, "erro interno"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		c, _ := New(srv.URL)
		err := c.do(context.Background(), "POST", "/x", "", nil, nil)
		if err == nil || vaulterrors.Message(err) != tc.want {
			t.Errorf("%d %s: got %v", tc.status, tc.body, err)
		}
		srv.Close()
	}
	var locked *autherrors.LockedError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(423)
		w.Write([]byte(`{"error":"locked","minutes":15}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL)
	if err := c.do(context.Background(), "POST", "/login", "", nil, nil); !errors.As(err, &locked) || locked.Minutes != 15 {
		t.Fatalf("got %v", err)
	}
}

func TestDoRefusesRedirects(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer target.Close()
	for _, code := range []int{301, 302, 307, 308} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/login", code)
		}))
		c, _ := New(srv.URL)
		err := c.do(context.Background(), "POST", "/login", "tok", map[string]string{"auth_hash": "x"}, nil)
		if err == nil || vaulterrors.Message(err) != "erro interno" {
			t.Errorf("%d: got %v", code, err)
		}
		srv.Close()
	}
	if hits != 0 {
		t.Fatalf("redirect followed %d times", hits)
	}
}
