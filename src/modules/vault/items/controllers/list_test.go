package controllers

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

func named(names ...string) []dto.Item {
	var out []dto.Item
	for _, n := range names {
		out = append(out, dto.Item{Name: n, Password: "p"})
	}
	return out
}

func TestList(t *testing.T) {
	boom := errors.New("db down")
	cases := []struct {
		name    string
		items   []dto.Item
		skipped int
		err     error
		want    string
	}{
		{"names", named("Amazon", "github", "Zoom"), 0, nil, "Amazon\ngithub\nZoom\n"},
		{"empty", nil, 0, nil, "cofre vazio\n"},
		{"skipped", named("Amazon"), 2, nil, "Amazon\naviso: 2 item(ns) ignorado(s) por falha de integridade\n"},
		{"empty skipped", nil, 1, nil, "cofre vazio\naviso: 1 item(ns) ignorado(s) por falha de integridade\n"},
		{"internal", nil, 0, boom, "erro interno\n"},
	}
	for _, c := range cases {
		s := session()
		list := func(_ context.Context, cs *cli.Session) ([]dto.Item, int, error) {
			if cs != s {
				t.Errorf("%s: session %v", c.name, cs)
			}
			return c.items, c.skipped, c.err
		}
		p, out := prompter("")
		if err := NewList(list)(context.Background(), p, s, ""); err != c.err {
			t.Errorf("%s: err %v", c.name, err)
		}
		if o := out.String(); o != c.want {
			t.Errorf("%s: out %q", c.name, o)
		}
	}
}

func TestListBrowsesInTUI(t *testing.T) {
	items := []dto.Item{
		{Name: "Amazon", Password: "p2"},
		{Name: "github", Username: "ana", Password: "p1", URL: "https://github.com", Notes: "n"},
	}
	list := func(context.Context, *cli.Session) ([]dto.Item, int, error) { return items, 1, nil }
	p, out := prompter("")
	var got [][]cli.Entry
	p.Browse = func(e []cli.Entry) { got = append(got, e) }
	if err := NewList(list)(context.Background(), p, session(), ""); err != nil {
		t.Fatal(err)
	}
	want := []cli.Entry{
		{Title: "Amazon", Fields: []cli.Field{{Label: "senha", Value: "p2", Secret: true}}},
		{Title: "github", Fields: []cli.Field{
			{Label: "usuário", Value: "ana"},
			{Label: "senha", Value: "p1", Secret: true},
			{Label: "url", Value: "https://github.com"},
			{Label: "notas", Value: "n"},
		}},
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("browsed %+v", got)
	}
	if o := out.String(); o != "aviso: 1 item(ns) ignorado(s) por falha de integridade\n" {
		t.Fatalf("names printed with browser: %q", o)
	}
}

func TestListEmptyDoesNotBrowse(t *testing.T) {
	list := func(context.Context, *cli.Session) ([]dto.Item, int, error) { return nil, 0, nil }
	p, out := prompter("")
	p.Browse = func([]cli.Entry) { t.Fatal("browsed an empty vault") }
	NewList(list)(context.Background(), p, session(), "")
	if out.String() != "cofre vazio\n" {
		t.Fatalf("out %q", out.String())
	}
}
