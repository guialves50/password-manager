package controllers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
)

func prompter(lines string, secrets ...string) (*cli.Prompter, *bytes.Buffer) {
	var out bytes.Buffer
	return &cli.Prompter{
		In:  bufio.NewReader(strings.NewReader(lines)),
		Out: &out,
		ReadSecret: func() ([]byte, error) {
			if len(secrets) == 0 {
				return nil, io.EOF
			}
			s := secrets[0]
			secrets = secrets[1:]
			return []byte(s), nil
		},
	}, &out
}

func TestLoginOpensShellAndZeroesKeyOnExit(t *testing.T) {
	s := &cli.Session{UserID: 1, Email: "alice@example.com", VaultKey: bytes.Repeat([]byte{9}, 32)}
	var got dto.Input
	login := func(_ context.Context, in dto.Input) (*cli.Session, error) {
		got = dto.Input{Email: in.Email, Password: bytes.Clone(in.Password)}
		return s, nil
	}
	p, out := prompter("alice@example.com\nfoo\nexit\nnot-read\n", "SenhaForte1")

	if err := New(login)(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got.Email != "alice@example.com" || string(got.Password) != "SenhaForte1" {
		t.Fatalf("input %q %q", got.Email, got.Password)
	}
	o := out.String()
	if !strings.HasSuffix(o, "pm> comando desconhecido\npm> ") || strings.Contains(o, "SenhaForte1") {
		t.Fatalf("out %q", o)
	}
	vk := bytes.Repeat([]byte{9}, 32)
	for _, leak := range []string{string(vk), hex.EncodeToString(vk), base64.StdEncoding.EncodeToString(vk), base64.RawURLEncoding.EncodeToString(vk)} {
		if strings.Contains(o, leak) {
			t.Fatalf("vault key leaked in output %q", o)
		}
	}
	if !bytes.Equal(s.VaultKey, make([]byte, 32)) {
		t.Fatalf("key not zeroed: %v", s.VaultKey)
	}
}

func TestLoginErrors(t *testing.T) {
	cases := []struct {
		name    string
		lines   string
		secrets []string
		err     error
		want    string
	}{
		{"invalid", "a@example.com\n", []string{"SenhaErrada1"}, autherrors.ErrInvalidCredentials, "email ou senha mestra inválidos\n"},
		{"locked", "a@example.com\n", []string{"SenhaErrada1"}, &autherrors.LockedError{Minutes: 15}, "conta bloqueada, tente novamente em 15 minutos\n"},
		{"internal", "a@example.com\n", []string{"SenhaErrada1"}, errors.New("db SenhaErrada1"), "erro interno\n"},
		{"eof email", "", nil, nil, "operação cancelada\n"},
		{"eof password", "a@example.com\n", nil, nil, "operação cancelada\n"},
	}
	for _, c := range cases {
		calls := 0
		login := func(context.Context, dto.Input) (*cli.Session, error) {
			calls++
			return nil, c.err
		}
		p, out := prompter(c.lines, c.secrets...)
		err := New(login)(context.Background(), p)
		o := out.String()
		if err == nil || !strings.HasSuffix(o, c.want) {
			t.Errorf("%s: err %v out %q", c.name, err, o)
		}
		if strings.Contains(o, "pm> ") || strings.Contains(o, "SenhaErrada1") {
			t.Errorf("%s: unexpected output %q", c.name, o)
		}
		if c.err == nil && calls != 0 {
			t.Errorf("%s: login called after EOF", c.name)
		}
	}
}
