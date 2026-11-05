package controllers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

type logoutSpy struct {
	tokens []string
}

func (l *logoutSpy) logout(_ context.Context, token string) error {
	l.tokens = append(l.tokens, token)
	return errors.New("ignored")
}

func TestLoginOpensShellAndZeroesKeyOnExit(t *testing.T) {
	s := &cli.Session{UserID: 1, Email: "alice@example.com", VaultKey: bytes.Repeat([]byte{9}, 32), Token: "tok"}
	spy := &logoutSpy{}
	var got dto.Input
	login := func(_ context.Context, in dto.Input) (*cli.Session, error) {
		got = dto.Input{Email: in.Email, Password: bytes.Clone(in.Password)}
		return s, nil
	}
	p, out := prompter("alice@example.com\nfoo\nexit\nnot-read\n", "SenhaForte1")

	if err := New(login, spy.logout, nil)(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(spy.tokens) != 1 || spy.tokens[0] != "tok" {
		t.Fatalf("logout tokens %q", spy.tokens)
	}
	if got.Email != "alice@example.com" || string(got.Password) != "SenhaForte1" {
		t.Fatalf("input %q %q", got.Email, got.Password)
	}
	o := out.String()
	if !strings.HasSuffix(o, "guardian> comando desconhecido\nguardian> ") || strings.Contains(o, "SenhaForte1") {
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

func TestLoginForwardsCommandsToShell(t *testing.T) {
	s := &cli.Session{UserID: 1, Email: "alice@example.com", VaultKey: bytes.Repeat([]byte{9}, 32)}
	login := func(context.Context, dto.Input) (*cli.Session, error) { return s, nil }
	var args []string
	cmds := map[string]cli.SessionCommand{"get": func(_ context.Context, p *cli.Prompter, cs *cli.Session, arg string) error {
		if cs != s || !bytes.Equal(cs.VaultKey, bytes.Repeat([]byte{9}, 32)) {
			t.Errorf("command session %+v", cs)
		}
		args = append(args, arg)
		fmt.Fprintln(p.Out, "ok")
		return nil
	}}
	p, out := prompter("alice@example.com\nget conta banco\nexit\n", "SenhaForte1")

	if err := New(login, (&logoutSpy{}).logout, cmds)(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 || args[0] != "conta banco" {
		t.Fatalf("args %q", args)
	}
	if o := out.String(); !strings.HasSuffix(o, "guardian> ok\nguardian> ") {
		t.Fatalf("out %q", o)
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
		{"invalid totp", "a@example.com\n", []string{"SenhaForte1"}, autherrors.ErrInvalidTOTP, "código 2FA inválido\n"},
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
		spy := &logoutSpy{}
		err := New(login, spy.logout, nil)(context.Background(), p)
		o := out.String()
		if err == nil || !strings.HasSuffix(o, c.want) {
			t.Errorf("%s: err %v out %q", c.name, err, o)
		}
		if strings.Contains(o, "guardian> ") || strings.Contains(o, "SenhaErrada1") {
			t.Errorf("%s: unexpected output %q", c.name, o)
		}
		if len(spy.tokens) != 0 {
			t.Errorf("%s: logout called %q", c.name, spy.tokens)
		}
		if c.err == nil && calls != 0 {
			t.Errorf("%s: login called after EOF", c.name)
		}
	}
}

func TestLoginLogsOutWhenShellEnds(t *testing.T) {
	expired := map[string]cli.SessionCommand{"list": func(_ context.Context, p *cli.Prompter, _ *cli.Session, _ string) error {
		fmt.Fprintln(p.Out, autherrors.Message(autherrors.ErrSessionExpired))
		return autherrors.ErrSessionExpired
	}}
	cases := []struct {
		name, lines, wantSuffix string
		cmds                    map[string]cli.SessionCommand
	}{
		{"logout", "alice@example.com\nlogout\nnot-read\n", "guardian> ", nil},
		{"eof", "alice@example.com\n", "guardian> \n", nil},
		{"expired", "alice@example.com\nlist\nlist\n", "guardian> sessão expirada, faça login novamente\n", expired},
	}
	for _, c := range cases {
		s := &cli.Session{UserID: 1, Email: "alice@example.com", VaultKey: bytes.Repeat([]byte{9}, 32), Token: "tok-" + c.name}
		spy := &logoutSpy{}
		login := func(context.Context, dto.Input) (*cli.Session, error) { return s, nil }
		p, out := prompter(c.lines, "SenhaForte1")
		if err := New(login, spy.logout, c.cmds)(context.Background(), p); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !strings.HasSuffix(out.String(), c.wantSuffix) || strings.Count(out.String(), "sessão expirada") > 1 {
			t.Errorf("%s: out %q", c.name, out.String())
		}
		if len(spy.tokens) != 1 || spy.tokens[0] != "tok-"+c.name {
			t.Errorf("%s: logout tokens %q", c.name, spy.tokens)
		}
		if !bytes.Equal(s.VaultKey, make([]byte, 32)) {
			t.Errorf("%s: key not zeroed", c.name)
		}
	}
}

func TestLoginAsksTOTPCodeOnDemand(t *testing.T) {
	var code string
	var codeErr error
	login := func(_ context.Context, in dto.Input) (*cli.Session, error) {
		code, codeErr = in.Code()
		return &cli.Session{Token: "tok"}, nil
	}
	p, out := prompter("a@example.com\n123456\nexit\n", "SenhaForte1")
	if err := New(login, (&logoutSpy{}).logout, nil)(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if code != "123456" || codeErr != nil || !strings.HasPrefix(out.String(), "email: senha mestra: \ncódigo 2FA: guardian> ") {
		t.Fatalf("code %q err %v out %q", code, codeErr, out.String())
	}
}

func TestLoginShowsCheckOnlyAfter2FA(t *testing.T) {
	for _, askCode := range []bool{true, false} {
		login := func(_ context.Context, in dto.Input) (*cli.Session, error) {
			if askCode {
				in.Code()
			}
			return &cli.Session{Token: "tok"}, nil
		}
		input := "a@example.com\nexit\n"
		if askCode {
			input = "a@example.com\n123456\nexit\n"
		}
		p, _ := prompter(input, "SenhaForte1")
		checks, checksAtShell := 0, -1
		p.ShowCheck = func() { checks++ }
		p.OnSession = func(s *cli.Session) {
			if s != nil {
				checksAtShell = checks
			}
		}
		if err := New(login, (&logoutSpy{}).logout, nil)(context.Background(), p); err != nil {
			t.Fatal(err)
		}
		want := 0
		if askCode {
			want = 1
		}
		if checks != want || checksAtShell != want {
			t.Errorf("askCode=%v: checks %d (before shell %d), want %d", askCode, checks, checksAtShell, want)
		}
	}
}

func TestLoginFailedCodeShowsNoCheck(t *testing.T) {
	login := func(_ context.Context, in dto.Input) (*cli.Session, error) {
		in.Code()
		return nil, autherrors.ErrInvalidTOTP
	}
	p, out := prompter("a@example.com\n000000\n", "SenhaForte1")
	checks := 0
	p.ShowCheck = func() { checks++ }
	if err := New(login, (&logoutSpy{}).logout, nil)(context.Background(), p); err == nil || checks != 0 || !strings.HasSuffix(out.String(), "código 2FA inválido\n") {
		t.Fatalf("err %v checks %d out %q", err, checks, out.String())
	}
}
