package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

func TestGet(t *testing.T) {
	boom := errors.New("db down")
	full := dto.Item{ID: "id-1", Name: "gmail", Username: "alice@gmail.com", Password: "S3nhaDoGmail", URL: "https://mail.google.com", Notes: "conta pessoal"}
	cases := []struct {
		name    string
		item    dto.Item
		skipped int
		err     error
		want    string
	}{
		{"all fields", full, 0, nil, "nome: gmail\nusuário: alice@gmail.com\nsenha: S3nhaDoGmail\nurl: https://mail.google.com\nnotas: conta pessoal\n"},
		{"optional empty", dto.Item{Name: "x", Password: "y"}, 0, nil, "nome: x\nsenha: y\n"},
		{"url empty", dto.Item{Name: "x", Username: "u", Password: "y", Notes: "n"}, 0, nil, "nome: x\nusuário: u\nsenha: y\nnotas: n\n"},
		{"url only", dto.Item{Name: "x", Password: "y", URL: "https://x"}, 0, nil, "nome: x\nsenha: y\nurl: https://x\n"},
		{"skipped", dto.Item{Name: "x", Password: "y"}, 1, nil, "nome: x\nsenha: y\naviso: 1 item(ns) ignorado(s) por falha de integridade\n"},
		{"not found", dto.Item{}, 0, vaulterrors.ErrNotFound, "item não encontrado\n"},
		{"not found skipped", dto.Item{}, 2, vaulterrors.ErrNotFound, "item não encontrado\naviso: 2 item(ns) ignorado(s) por falha de integridade\n"},
		{"internal", dto.Item{}, 0, boom, "erro interno\n"},
	}
	for _, c := range cases {
		s := session()
		var names []string
		get := func(_ context.Context, cs *cli.Session, name string) (dto.Item, int, error) {
			if cs != s {
				t.Errorf("%s: session %v", c.name, cs)
			}
			names = append(names, name)
			return c.item, c.skipped, c.err
		}
		p, out := prompter("")
		if err := NewGet(get, nil)(context.Background(), p, s, "conta GMAIL"); err != c.err {
			t.Errorf("%s: err %v", c.name, err)
		}
		if len(names) != 1 || names[0] != "conta GMAIL" {
			t.Errorf("%s: names %q", c.name, names)
		}
		if o := out.String(); o != c.want {
			t.Errorf("%s: out %q", c.name, o)
		}
	}
}

func TestGetWithoutNamePrintsUsage(t *testing.T) {
	calls := 0
	get := func(context.Context, *cli.Session, string) (dto.Item, int, error) { calls++; return dto.Item{}, 0, nil }
	p, out := prompter("")
	if err := NewGet(get, nil)(context.Background(), p, session(), ""); err != nil || calls != 0 {
		t.Fatalf("err %v calls %d", err, calls)
	}
	if o := out.String(); o != "uso: get <nome>\n" {
		t.Fatalf("out %q", o)
	}
}
