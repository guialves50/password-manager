package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
)

func tlsServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, path
}

func TestCACertTrustsSelfSignedServer(t *testing.T) {
	srv, ca := tlsServer(t)
	t.Setenv("PM_CA_CERT", ca)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.do(context.Background(), "POST", "/x", "", nil, nil); err != nil {
		t.Fatalf("trusted server: %v", err)
	}
}

func TestWithoutCACertSelfSignedIsUnreachable(t *testing.T) {
	srv, _ := tlsServer(t)
	t.Setenv("PM_CA_CERT", "")
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.do(context.Background(), "POST", "/x", "", nil, nil); !errors.Is(err, autherrors.ErrUnreachable) {
		t.Fatalf("got %v", err)
	}
}

func TestCACertTrustsOnlyThatCertificate(t *testing.T) {
	srv, _ := tlsServer(t)
	// every httptest TLS server shares one built-in certificate, so make a distinct one
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.crt")
	os.WriteFile(other, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	t.Setenv("PM_CA_CERT", other)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.do(context.Background(), "POST", "/x", "", nil, nil); !errors.Is(err, autherrors.ErrUnreachable) {
		t.Fatalf("server with another certificate accepted: %v", err)
	}
}

func TestCACertInvalid(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "x.crt")
	os.WriteFile(notPEM, []byte("not a certificate"), 0o600)
	for _, path := range []string{notPEM, filepath.Join(t.TempDir(), "missing.crt")} {
		t.Setenv("PM_CA_CERT", path)
		if c, err := New("https://127.0.0.1:8080"); !errors.Is(err, autherrors.ErrCACert) || c != nil {
			t.Errorf("%s: got %v, %v", path, c, err)
		}
	}
	if autherrors.Message(autherrors.ErrCACert) != "PM_CA_CERT não aponta para um certificado PEM válido" {
		t.Fatalf("message %q", autherrors.Message(autherrors.ErrCACert))
	}
}
