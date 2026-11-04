package controllers

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
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

const newKey = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"

func TestRecoverHappyPath(t *testing.T) {
	var got dto.Input
	recover := func(_ context.Context, in dto.Input) (dto.Output, error) {
		got = dto.Input{Email: in.Email, RecoveryKey: bytes.Clone(in.RecoveryKey), Password: bytes.Clone(in.Password), Confirm: bytes.Clone(in.Confirm)}
		return dto.Output{RecoveryKey: newKey}, nil
	}
	p, out := prompter("alice@example.com\n", "OLDK-EYXX", "SenhaNova1", "SenhaNova1")

	if err := New(recover)(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got.Email != "alice@example.com" || string(got.RecoveryKey) != "OLDK-EYXX" || string(got.Password) != "SenhaNova1" || string(got.Confirm) != "SenhaNova1" {
		t.Fatalf("input %q %q %q %q", got.Email, got.RecoveryKey, got.Password, got.Confirm)
	}
	o := out.String()
	for _, want := range []string{"senha mestra redefinida\n", "chave de recuperação: " + newKey + "\n", "não pode ser exibida novamente"} {
		if !strings.Contains(o, want) {
			t.Fatalf("missing %q in %q", want, o)
		}
	}
	if strings.Contains(o, "SenhaNova1") || strings.Contains(o, "OLDK-EYXX") {
		t.Fatalf("secret leaked: %q", o)
	}
}

func TestRecoverErrors(t *testing.T) {
	cases := []struct {
		name    string
		lines   string
		secrets []string
		err     error
		want    string
	}{
		{"invalid", "a@example.com\n", []string{"OLDK-EYXX", "SenhaNova1", "SenhaNova1"}, autherrors.ErrInvalidRecovery, "email ou chave de recuperação inválidos\n"},
		{"locked", "a@example.com\n", []string{"OLDK-EYXX", "SenhaNova1", "SenhaNova1"}, &autherrors.LockedError{Minutes: 15}, "conta bloqueada, tente novamente em 15 minutos\n"},
		{"length", "a@example.com\n", []string{"OLDK-EYXX", "SenhaNova1", "SenhaNova1"}, autherrors.ErrPasswordLength, "a senha mestra deve ter entre 8 e 128 caracteres\n"},
		{"case", "a@example.com\n", []string{"OLDK-EYXX", "SenhaNova1", "SenhaNova1"}, autherrors.ErrPasswordCase, "a senha mestra deve conter letras maiúsculas e minúsculas\n"},
		{"mismatch", "a@example.com\n", []string{"OLDK-EYXX", "SenhaNova1", "SenhaNova1"}, autherrors.ErrPasswordMismatch, "as senhas não conferem\n"},
		{"internal", "a@example.com\n", []string{"OLDK-EYXX", "SenhaNova1", "SenhaNova1"}, errors.New("db SenhaNova1"), "erro interno\n"},
		{"eof email", "", nil, nil, "operação cancelada\n"},
		{"eof key", "a@example.com\n", nil, nil, "operação cancelada\n"},
		{"eof password", "a@example.com\n", []string{"OLDK-EYXX"}, nil, "operação cancelada\n"},
		{"eof confirm", "a@example.com\n", []string{"OLDK-EYXX", "SenhaNova1"}, nil, "operação cancelada\n"},
	}
	for _, c := range cases {
		calls := 0
		recover := func(context.Context, dto.Input) (dto.Output, error) {
			calls++
			return dto.Output{}, c.err
		}
		p, out := prompter(c.lines, c.secrets...)
		err := New(recover)(context.Background(), p)
		o := out.String()
		if err == nil || !strings.HasSuffix(o, c.want) {
			t.Errorf("%s: err %v out %q", c.name, err, o)
		}
		if strings.Contains(o, "redefinida") || strings.Contains(o, "SenhaNova1") || strings.Contains(o, "OLDK-EYXX") {
			t.Errorf("%s: unexpected output %q", c.name, o)
		}
		if c.err == nil && calls != 0 {
			t.Errorf("%s: recover called after EOF", c.name)
		}
	}
}
