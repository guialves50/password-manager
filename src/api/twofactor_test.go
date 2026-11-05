package api

import (
	"context"
	"errors"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
)

func TestSetup2FA(t *testing.T) {
	c, got := fakeServer(t, 200, `{"secret":"ABC","uri":"otpauth://totp/x"}`)
	out, err := c.Setup2FA(context.Background(), &cli.Session{Token: "tok"})
	if err != nil || out.Secret != "ABC" || out.URI != "otpauth://totp/x" {
		t.Fatalf("%+v %v", out, err)
	}
	expect(t, got, "POST", "/2fa/setup", "Bearer tok", nil)
}

func TestConfirm2FA(t *testing.T) {
	c, got := fakeServer(t, 204, "")
	if err := c.Confirm2FA(context.Background(), &cli.Session{Token: "tok"}, "123456"); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/2fa/confirm", "Bearer tok", map[string]any{"code": "123456"})
	c, _ = fakeServer(t, 401, `{"error":"invalid_totp"}`)
	if err := c.Confirm2FA(context.Background(), &cli.Session{Token: "tok"}, "1"); !errors.Is(err, autherrors.ErrInvalidTOTP) {
		t.Fatal(err)
	}
}
