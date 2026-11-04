package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	"gorm.io/gorm"
)

func TestRunDispatch(t *testing.T) {
	calls := 0
	routes := map[string]cli.Command{
		"login": func(context.Context, *cli.Prompter) error { calls++; return nil },
		"fail":  func(context.Context, *cli.Prompter) error { calls++; return errors.New("x") },
	}
	p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("")), Out: &bytes.Buffer{}}
	cases := []struct {
		args  []string
		code  int
		calls int
		usage bool
	}{
		{[]string{"login"}, 0, 1, false},
		{[]string{"fail"}, 1, 1, false},
		{[]string{"nope"}, 2, 0, true},
		{nil, 2, 0, true},
	}
	for _, c := range cases {
		calls = 0
		var stderr bytes.Buffer
		if code := run(c.args, routes, p, &stderr); code != c.code || calls != c.calls {
			t.Errorf("%v: code %d calls %d", c.args, code, calls)
		}
		if got := stderr.String() == "uso: pm <register|login|recover>\n"; got != c.usage {
			t.Errorf("%v: stderr %q", c.args, stderr.String())
		}
	}
}

func TestStartUnreachableDatabase(t *testing.T) {
	var out, stderr bytes.Buffer
	p := &cli.Prompter{In: bufio.NewReader(strings.NewReader("")), Out: &out}
	connect := func() (*gorm.DB, error) { return nil, errors.New("dial tcp: refused") }
	if code := start(connect, []string{"login"}, p, &stderr); code != 1 {
		t.Fatalf("code %d", code)
	}
	if stderr.String() != "não foi possível conectar ao banco de dados\n" || out.Len() != 0 {
		t.Fatalf("stderr %q out %q", stderr.String(), out.String())
	}
}
