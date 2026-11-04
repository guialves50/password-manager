package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
)

func TestList(t *testing.T) {
	boom := errors.New("db down")
	cases := []struct {
		name    string
		names   []string
		skipped int
		err     error
		want    string
	}{
		{"names", []string{"Amazon", "github", "Zoom"}, 0, nil, "Amazon\ngithub\nZoom\n"},
		{"empty", nil, 0, nil, "cofre vazio\n"},
		{"skipped", []string{"Amazon"}, 2, nil, "Amazon\naviso: 2 item(ns) ignorado(s) por falha de integridade\n"},
		{"empty skipped", nil, 1, nil, "cofre vazio\naviso: 1 item(ns) ignorado(s) por falha de integridade\n"},
		{"internal", nil, 0, boom, "erro interno\n"},
	}
	for _, c := range cases {
		s := session()
		list := func(_ context.Context, cs *cli.Session) ([]string, int, error) {
			if cs != s {
				t.Errorf("%s: session %v", c.name, cs)
			}
			return c.names, c.skipped, c.err
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
