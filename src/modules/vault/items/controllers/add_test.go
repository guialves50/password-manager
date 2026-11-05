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
	"github.com/guialves50/password-manager/src/modules/vault/generator"
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

const generated = "Ger4d@SenhaForte#20x"

func fixedGen(n int) (string, error) { return generated, nil }

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
	asked := 0
	gen := func(n int) (string, error) { asked = n; return generated, nil }
	p, out := prompter("gmail\nalice@gmail.com\n\nhttps://mail.google.com\nconta pessoal\n")

	if err := NewAdd(add, gen)(context.Background(), p, s, ""); err != nil {
		t.Fatal(err)
	}
	want := dto.Item{Name: "gmail", Username: "alice@gmail.com", Password: generated, URL: "https://mail.google.com", Notes: "conta pessoal"}
	if len(got) != 1 || got[0] != want || asked != 20 {
		t.Fatalf("add got %+v, length %d", got, asked)
	}
	if o := out.String(); o != "nome: usuário: comprimento (20): url: notas: item salvo\n" {
		t.Fatalf("out %q", o)
	}
}

func TestAddCustomLength(t *testing.T) {
	for line, want := range map[string]int{"32": 32, " 8 ": 8, "128": 128} {
		var got dto.Item
		add := func(_ context.Context, _ *cli.Session, in dto.Item) (int, error) { got = in; return 0, nil }
		p, _ := prompter("gmail\n\n" + line + "\n\n\n")
		if err := NewAdd(add, generator.Generate)(context.Background(), p, session(), ""); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if len(got.Password) != want {
			t.Errorf("%q: password length %d", line, len(got.Password))
		}
	}
}

func TestAddInvalidLength(t *testing.T) {
	for _, line := range []string{"abc", "7", "129", "0", "-5", "2.5", "20a"} {
		calls := 0
		add := func(context.Context, *cli.Session, dto.Item) (int, error) { calls++; return 0, nil }
		p, out := prompter("gmail\nalice\n" + line + "\nhttps://x\nnotas\n")
		err := NewAdd(add, generator.Generate)(context.Background(), p, session(), "")
		if !errors.Is(err, vaulterrors.ErrGenLength) || calls != 0 {
			t.Errorf("%q: err %v calls %d", line, err, calls)
		}
		if o := out.String(); o != "nome: usuário: comprimento (20): o comprimento deve ser um número entre 8 e 128\n" {
			t.Errorf("%q: out %q", line, o)
		}
	}
}

func TestAddGeneratorFailure(t *testing.T) {
	calls := 0
	add := func(context.Context, *cli.Session, dto.Item) (int, error) { calls++; return 0, nil }
	gen := func(int) (string, error) { return "", errors.New("rand") }
	p, out := prompter("gmail\n\n\n\n\n")
	if err := NewAdd(add, gen)(context.Background(), p, session(), ""); err == nil || calls != 0 {
		t.Fatalf("err %v calls %d", err, calls)
	}
	if o := out.String(); o != "nome: usuário: comprimento (20): erro interno\n" {
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
		p, out := prompter("gmail\n\n\n\n\n")
		err := NewAdd(add, fixedGen)(context.Background(), p, session(), "")
		if err != c.err {
			t.Errorf("%v: err %v", c.err, err)
		}
		if o := out.String(); o != "nome: usuário: comprimento (20): url: notas: "+c.want {
			t.Errorf("%v: out %q", c.err, o)
		}
	}
}

func TestAddEOFAtAnyPromptCancels(t *testing.T) {
	cases := []struct {
		name  string
		lines string
		want  string
	}{
		{"nome", "", "nome: "},
		{"usuário", "gmail\n", "nome: usuário: "},
		{"comprimento", "gmail\nalice\n", "nome: usuário: comprimento (20): "},
		{"url", "gmail\nalice\n\n", "nome: usuário: comprimento (20): url: "},
		{"notas", "gmail\nalice\n\nhttps://x\n", "nome: usuário: comprimento (20): url: notas: "},
	}
	for _, c := range cases {
		calls := 0
		add := func(context.Context, *cli.Session, dto.Item) (int, error) { calls++; return 0, nil }
		p, out := prompter(c.lines)
		err := NewAdd(add, fixedGen)(context.Background(), p, session(), "")
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
		p, out := prompter("gmail\n\n\n\n\n")
		if err := NewAdd(add, fixedGen)(context.Background(), p, session(), ""); err != c.err {
			t.Errorf("%v: err %v", c.err, err)
		}
		if o := out.String(); o != "nome: usuário: comprimento (20): url: notas: "+c.want {
			t.Errorf("%v: out %q", c.err, o)
		}
	}
}
