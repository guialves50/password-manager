package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func newSession() *Session {
	return &Session{UserID: 1, Email: "a@b.com", VaultKey: bytes.Repeat([]byte{7}, 32)}
}

func assertZeroed(t *testing.T, s *Session) {
	t.Helper()
	if len(s.VaultKey) != 32 || !bytes.Equal(s.VaultKey, make([]byte, 32)) {
		t.Fatalf("key not zeroed: %v", s.VaultKey)
	}
}

func run(in string, s *Session) string {
	return runCmds(in, s, nil)
}

func runCmds(in string, s *Session, cmds map[string]SessionCommand) string {
	var out bytes.Buffer
	Shell(context.Background(), &Prompter{In: bufio.NewReader(strings.NewReader(in)), Out: &out}, s, cmds)
	return out.String()
}

func TestShellExitCommandsStopAndZeroKey(t *testing.T) {
	for _, cmd := range []string{"exit", "logout", "  exit  "} {
		s := newSession()
		out := run(cmd+"\nfoo\n", s)
		if out != "pm> " {
			t.Errorf("%q: out %q", cmd, out)
		}
		assertZeroed(t, s)
	}
}

func TestShellEOFZeroesKey(t *testing.T) {
	s := newSession()
	out := run("", s)
	if !strings.HasPrefix(out, "pm> ") {
		t.Fatalf("out %q", out)
	}
	assertZeroed(t, s)
}

func TestShellUnknownCommandContinues(t *testing.T) {
	s := newSession()
	out := run("foo\nexit\n", s)
	if out != "pm> comando desconhecido\npm> " {
		t.Fatalf("out %q", out)
	}
	assertZeroed(t, s)
}

func TestSessionClose(t *testing.T) {
	s := newSession()
	s.Close()
	assertZeroed(t, s)
}

func TestShellDispatchesRestOfLineAsArg(t *testing.T) {
	cases := map[string]string{
		"get conta banco\n":       "conta banco",
		"  get   conta banco  \n": "conta banco",
		"get\n":                   "",
	}
	for line, want := range cases {
		s := newSession()
		var got []string
		cmds := map[string]SessionCommand{"get": func(_ context.Context, p *Prompter, cs *Session, arg string) error {
			if cs != s || bytes.Equal(cs.VaultKey, make([]byte, 32)) {
				t.Errorf("%q: command got session %v", line, cs)
			}
			got = append(got, arg)
			fmt.Fprintln(p.Out, "ok")
			return nil
		}}
		out := runCmds(line+"exit\n", s, cmds)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: args %q, want %q", line, got, want)
		}
		if out != "pm> ok\npm> " {
			t.Errorf("%q: out %q", line, out)
		}
		assertZeroed(t, s)
	}
}

func TestShellUnknownCommandWithRoutesContinues(t *testing.T) {
	s := newSession()
	calls := 0
	cmds := map[string]SessionCommand{"list": func(context.Context, *Prompter, *Session, string) error { calls++; return nil }}
	out := runCmds("foo\nexit list\nlist\nexit\n", s, cmds)
	if out != "pm> comando desconhecido\npm> comando desconhecido\npm> pm> " || calls != 1 {
		t.Fatalf("out %q calls %d", out, calls)
	}
	assertZeroed(t, s)
}

func TestShellCommandEOFStopsAndZeroesKey(t *testing.T) {
	for _, ret := range []error{io.EOF, fmt.Errorf("prompt: %w", io.EOF)} {
		s := newSession()
		listed := 0
		cmds := map[string]SessionCommand{
			"add": func(_ context.Context, p *Prompter, _ *Session, _ string) error {
				if name, err := p.Line("nome: "); err != nil || name != "gmail" {
					t.Errorf("line %q, %v", name, err)
				}
				return ret
			},
			"list": func(context.Context, *Prompter, *Session, string) error { listed++; return nil },
		}
		out := runCmds("add\ngmail\nlist\n", s, cmds)
		if out != "pm> nome: " || listed != 0 {
			t.Errorf("%v: out %q listed %d", ret, out, listed)
		}
		assertZeroed(t, s)
	}
}

func TestShellCommandErrorContinues(t *testing.T) {
	s := newSession()
	listed := 0
	cmds := map[string]SessionCommand{
		"add":  func(context.Context, *Prompter, *Session, string) error { return errors.New("db down") },
		"list": func(context.Context, *Prompter, *Session, string) error { listed++; return nil },
	}
	out := runCmds("add\nlist\nexit\n", s, cmds)
	if out != "pm> pm> pm> " || listed != 1 {
		t.Fatalf("out %q listed %d", out, listed)
	}
	assertZeroed(t, s)
}
