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
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
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

func session() *cli.Session {
	return &cli.Session{UserID: 42, Email: "alice@example.com", VaultKey: bytes.Repeat([]byte{7}, 32)}
}

func TestAddHappyPath(t *testing.T) {
	s := session()
	var got []dto.Item
	add := func(_ context.Context, cs *cli.Session, in dto.Item) (int, error) {
		if cs != s {
			t.Errorf("session %v", cs)
		}
		got = append(got, in)
		return 0, nil
	}
	p, out := prompter("gmail\nalice@gmail.com\nhttps://mail.google.com\nconta pessoal\n", "S3nhaDoGmail")

	if err := NewAdd(add)(context.Background(), p, s, ""); err != nil {
		t.Fatal(err)
	}
	want := dto.Item{Name: "gmail", Username: "alice@gmail.com", Password: "S3nhaDoGmail", URL: "https://mail.google.com", Notes: "conta pessoal"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("add got %+v", got)
	}
	if o := out.String(); o != "nome: usuário: senha: \nurl: notas: item salvo\n" {
		t.Fatalf("out %q", o)
	}
}

func TestAddErrors(t *testing.T) {
	boom := errors.New("db down S3nhaDoGmail")
	cases := []struct {
		err  error
		want string
	}{
		{vaulterrors.ErrNameLength, "o nome deve ter entre 1 e 100 caracteres\n"},
		{vaulterrors.ErrPasswordLength, "a senha deve ter entre 1 e 1024 caracteres\n"},
		{vaulterrors.ErrUsernameLength, "usuário excede 254 caracteres\n"},
		{vaulterrors.ErrURLLength, "URL excede 2048 caracteres\n"},
		{vaulterrors.ErrNotesLength, "notas excedem 4096 caracteres\n"},
		{vaulterrors.ErrNameTaken, "já existe um item com esse nome\n"},
		{vaulterrors.ErrInvalidText, "o item contém texto que não é UTF-8 válido\n"},
		{boom, "erro interno\n"},
	}
	for _, c := range cases {
		add := func(context.Context, *cli.Session, dto.Item) (int, error) { return 0, c.err }
		p, out := prompter("gmail\n\n\n\n", "S3nhaDoGmail")
		err := NewAdd(add)(context.Background(), p, session(), "")
		if err != c.err {
			t.Errorf("%v: err %v", c.err, err)
		}
		if o := out.String(); o != "nome: usuário: senha: \nurl: notas: "+c.want {
			t.Errorf("%v: out %q", c.err, o)
		}
	}
}

func TestAddEOFAtAnyPromptCancels(t *testing.T) {
	cases := []struct {
		name    string
		lines   string
		secrets []string
		want    string
	}{
		{"nome", "", nil, "nome: "},
		{"usuário", "gmail\n", nil, "nome: usuário: "},
		{"senha", "gmail\nalice\n", nil, "nome: usuário: senha: \n"},
		{"url", "gmail\nalice\n", []string{"S3nhaDoGmail"}, "nome: usuário: senha: \nurl: "},
		{"notas", "gmail\nalice\nhttps://x\n", []string{"S3nhaDoGmail"}, "nome: usuário: senha: \nurl: notas: "},
	}
	for _, c := range cases {
		calls := 0
		add := func(context.Context, *cli.Session, dto.Item) (int, error) { calls++; return 0, nil }
		p, out := prompter(c.lines, c.secrets...)
		err := NewAdd(add)(context.Background(), p, session(), "")
		if !errors.Is(err, io.EOF) || calls != 0 {
			t.Errorf("%s: err %v calls %d", c.name, err, calls)
		}
		if o := out.String(); o != c.want+"operação cancelada\n" {
			t.Errorf("%s: out %q", c.name, o)
		}
	}
}

func TestAddWarnsAboutSkippedItems(t *testing.T) {
	warn := "aviso: 2 item(ns) ignorado(s) por falha de integridade\n"
	cases := []struct {
		err  error
		want string
	}{
		{nil, "item salvo\n" + warn},
		{vaulterrors.ErrNameTaken, "já existe um item com esse nome\n" + warn},
	}
	for _, c := range cases {
		add := func(context.Context, *cli.Session, dto.Item) (int, error) { return 2, c.err }
		p, out := prompter("gmail\n\n\n\n", "S3nhaDoGmail")
		if err := NewAdd(add)(context.Background(), p, session(), ""); err != c.err {
			t.Errorf("%v: err %v", c.err, err)
		}
		if o := out.String(); o != "nome: usuário: senha: \nurl: notas: "+c.want {
			t.Errorf("%v: out %q", c.err, o)
		}
	}
}
