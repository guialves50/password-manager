package cli

import (
	"bufio"
	"bytes"
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
	var out bytes.Buffer
	Shell(bufio.NewReader(strings.NewReader(in)), &out, s)
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
