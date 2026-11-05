package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/cli"
	"gorm.io/gorm"
)

const usageLine = "uso: guardian <serve|register|login|recover>\n"

func TestRunDispatch(t *testing.T) {
	calls := 0
	routes := map[string]cli.Command{
		"login": func(context.Context, *cli.Prompter) error { calls++; return nil },
		"fail":  func(context.Context, *cli.Prompter) error { calls++; return errors.New("x") },
	}
	p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("")), Out: &bytes.Buffer{}}
	cases := []struct {
		args  []string
		code  int
		calls int
		usage bool
	}{
		{[]string{"login"}, 0, 1, false},
		{[]string{"fail"}, 1, 1, false},
		{[]string{"nope"}, 2, 0, true},
		{nil, 2, 0, true},
	}
	for _, c := range cases {
		calls = 0
		var stderr bytes.Buffer
		if code := run(c.args, routes, p, &stderr); code != c.code || calls != c.calls {
			t.Errorf("%v: code %d calls %d", c.args, code, calls)
		}
		if got := stderr.String() == usageLine; got != c.usage {
			t.Errorf("%v: stderr %q", c.args, stderr.String())
		}
	}
}

func TestStartUsage(t *testing.T) {
	t.Setenv("PM_SERVER", "http://exemplo.com")
	for _, args := range [][]string{nil, {"nope"}, {""}} {
		var out, stderr bytes.Buffer
		p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("")), Out: &out}
		if code := start(args, p, &stderr); code != 2 || stderr.String() != usageLine || out.Len() != 0 {
			t.Errorf("%v: code %d stderr %q out %q", args, code, stderr.String(), out.String())
		}
	}
}

func TestStartInsecureServer(t *testing.T) {
	t.Setenv("PM_SERVER", "http://exemplo.com")
	for _, cmd := range []string{"register", "login", "recover"} {
		var out, stderr bytes.Buffer
		p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("a@b.com\n")), Out: &out}
		if code := start([]string{cmd}, p, &stderr); code != 1 || stderr.String() != "use https para servidores fora do localhost\n" || out.Len() != 0 {
			t.Errorf("%s: code %d stderr %q out %q", cmd, code, stderr.String(), out.String())
		}
	}
}

func TestStartUnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	t.Setenv("PM_SERVER", srv.URL)
	var out bytes.Buffer
	p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("a@b.com\n")), Out: &out, ReadSecret: func() ([]byte, error) { return []byte("SenhaForte1"), nil }}
	if code := start([]string{"login"}, p, io.Discard); code != 1 || !strings.HasSuffix(out.String(), "não foi possível conectar ao servidor\n") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

func noConnect(t *testing.T) func() (*gorm.DB, error) {
	return func() (*gorm.DB, error) {
		t.Error("connected to the database")
		return nil, errors.New("unexpected")
	}
}

func TestServeTLSPairRequired(t *testing.T) {
	for _, env := range [][2]string{{"PM_TLS_CERT", "PM_TLS_KEY"}, {"PM_TLS_KEY", "PM_TLS_CERT"}} {
		t.Setenv(env[0], "/tmp/x.pem")
		t.Setenv(env[1], "")
		var out, stderr bytes.Buffer
		if code := serve(noConnect(t), &out, &stderr); code != 1 || stderr.String() != "PM_TLS_CERT e PM_TLS_KEY devem ser definidos juntos\n" || out.Len() != 0 {
			t.Errorf("%s only: code %d stderr %q", env[0], code, stderr.String())
		}
	}
}

func TestServeRejectsBadSecret(t *testing.T) {
	for _, s := range []string{"zz", strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
		t.Setenv("PM_SERVER_SECRET", s)
		var stderr bytes.Buffer
		if code := serve(noConnect(t), io.Discard, &stderr); code != 1 || stderr.String() != "PM_SERVER_SECRET deve ter 32 bytes em hexadecimal\n" {
			t.Errorf("%q: code %d stderr %q", s, code, stderr.String())
		}
	}
}

func TestServeDatabaseFailure(t *testing.T) {
	t.Setenv("PM_SERVER_SECRET", strings.Repeat("ab", 32))
	var out, stderr bytes.Buffer
	connect := func() (*gorm.DB, error) { return nil, errors.New("dial tcp: refused") }
	if code := serve(connect, &out, &stderr); code != 1 || stderr.String() != "não foi possível preparar o banco de dados\n" || out.Len() != 0 {
		t.Fatalf("code %d stderr %q out %q", code, stderr.String(), out.String())
	}
}

func listening(t *testing.T, stderr io.Writer) string {
	t.Helper()
	t.Setenv("PM_ADDR", "127.0.0.1:0")
	r, w := io.Pipe()
	go serve(func() (*gorm.DB, error) { return &gorm.DB{}, nil }, w, stderr)
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "servidor ouvindo em 127.0.0.1:") {
		t.Fatalf("line %q, %v", line, err)
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "servidor ouvindo em "))
}

func TestServeHTTP(t *testing.T) {
	var stderr bytes.Buffer
	addr := listening(t, &stderr)
	if !strings.HasPrefix(stderr.String(), "aviso: PM_SERVER_SECRET não definido") || !strings.Contains(stderr.String(), "contas com 2FA não conseguem logar após reiniciar") {
		t.Fatalf("no secret warning: %q", stderr.String())
	}
	res, err := http.Post("http://"+addr+"/logout", "application/json", nil)
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("logout: %v %v", res, err)
	}
}

func TestServeTLSOnly(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	t.Setenv("PM_TLS_CERT", filepath.Join(dir, "cert.pem"))
	t.Setenv("PM_TLS_KEY", filepath.Join(dir, "missing.pem"))
	t.Setenv("PM_SERVER_SECRET", strings.Repeat("ab", 32))
	var stderr bytes.Buffer
	if code := serve(noConnect(t), io.Discard, &stderr); code != 1 || stderr.String() != "não foi possível carregar o certificado TLS\n" {
		t.Fatalf("bad key file: code %d stderr %q", code, stderr.String())
	}

	t.Setenv("PM_TLS_KEY", filepath.Join(dir, "key.pem"))
	addr := listening(t, io.Discard)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	res, err := client.Post("https://"+addr+"/logout", "application/json", nil)
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("https logout: %v %v", res, err)
	}
	res, err = http.Post("http://"+addr+"/logout", "application/json", nil)
	if err == nil && res.StatusCode == 401 {
		t.Fatal("plain http served alongside TLS")
	}
}

func TestHomeDispatchesUntilExit(t *testing.T) {
	var out bytes.Buffer
	p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("\n  login  \nserve\nlogin\nexit\nlogin\n")), Out: &out}
	calls := 0
	home(map[string]cli.Command{"login": func(context.Context, *cli.Prompter) error { calls++; return nil }}, p)
	if calls != 2 || out.String() != "comando desconhecido\n" {
		t.Fatalf("calls %d out %q", calls, out.String())
	}
	calls = 0
	home(map[string]cli.Command{"login": func(context.Context, *cli.Prompter) error { calls++; return nil }}, &cli.Prompter{In: bufio.NewReader(strings.NewReader("login\n")), Out: io.Discard})
	if calls != 1 {
		t.Fatalf("EOF: calls %d", calls)
	}
}
