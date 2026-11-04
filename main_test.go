package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
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
