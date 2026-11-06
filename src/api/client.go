package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
)

type Client struct {
	base string
	http *http.Client
}

// New trusts the system TLS roots, or only the certificate in PM_CA_CERT
// when it is set (a self-signed server certificate, for example).
func New(rawURL string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || !secure(u) {
		return nil, autherrors.ErrInsecureServer
	}
	hc := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if path := os.Getenv("PM_CA_CERT"); path != "" {
		pem, err := os.ReadFile(path)
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return nil, autherrors.ErrCACert
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		hc.Transport = t
	}
	return &Client{base: strings.TrimRight(u.String(), "/"), http: hc}, nil
}

func secure(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	}
	return false
}

func (c *Client) do(ctx context.Context, method, path, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", autherrors.ErrUnreachable, err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return decodeError(res)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func decodeError(res *http.Response) error {
	var e struct {
		Error   string `json:"error"`
		Minutes int    `json:"minutes"`
	}
	json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&e)
	if res.StatusCode == http.StatusServiceUnavailable {
		switch e.Error {
		case "busy":
			return autherrors.ErrBusy
		case "totp_unavailable":
			return autherrors.ErrTOTPUnavailable
		case "totp_unreadable":
			return autherrors.ErrTOTPUnreadable
		}
	}
	if res.StatusCode < 500 {
		switch e.Error {
		case "email_taken":
			return autherrors.ErrEmailTaken
		case "invalid_credentials":
			return autherrors.ErrInvalidCredentials
		case "invalid_recovery":
			return autherrors.ErrInvalidRecovery
		case "unauthorized":
			return autherrors.ErrSessionExpired
		case "totp_required":
			return autherrors.ErrTOTPRequired
		case "invalid_totp":
			return autherrors.ErrInvalidTOTP
		case "totp_enabled":
			return autherrors.ErrTOTPEnabled
		case "no_pending":
			return autherrors.ErrNoPendingTOTP
		case "not_found":
			return vaulterrors.ErrNotFound
		case "locked":
			if e.Minutes > 0 {
				return &autherrors.LockedError{Minutes: e.Minutes}
			}
		}
	}
	return fmt.Errorf("api: status %d, code %q", res.StatusCode, e.Error)
}
