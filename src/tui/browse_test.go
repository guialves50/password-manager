package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/cli"
)

func vault(names ...string) []cli.Entry {
	var out []cli.Entry
	for _, n := range names {
		out = append(out, cli.Entry{Title: n, Fields: []cli.Field{
			{Label: "usuário", Value: "ana@" + n},
			{Label: "senha", Value: "S3nha-" + n, Secret: true},
		}})
	}
	return out
}

// openBox starts `list`'s Browse and skips past the opening morph.
func openBox(t *testing.T, entries []cli.Entry) (*UI, *clock, chan struct{}) {
	t.Helper()
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	u := New("x")
	u.now = c.now
	p := u.Prompter()
	u.Write([]byte("guardian> list\n"))
	done := make(chan struct{})
	go func() { p.Browse(entries); close(done) }()
	waitFor(t, u, func() bool { return u.browser != nil })
	c.t = c.t.Add(boxMorph)
	return u, c, done
}

func screen(u *UI) string { return strings.Join(plain(u.Render(80, 30)), "\n") }

func TestBoxFormsFromShieldThenShowsList(t *testing.T) {
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	u := New("x")
	u.now = c.now
	p := u.Prompter()
	u.Write([]byte("guardian> list\n"))
	go p.Browse(vault("Amazon", "github", "Zoom"))
	waitFor(t, u, func() bool { return u.browser != nil })

	c.t = c.t.Add(boxMorph / 2)
	mid := center(u.Render(80, 30))
	if !strings.Contains(mid, fmt.Sprintf("38;5;%dm", boxColor)) || strings.Contains(plain([]string{mid})[0], "Amazon") || strings.Contains(mid, "guardian> list") {
		t.Fatal("box not forming from the shield")
	}
	c.t = c.t.Add(boxMorph / 2)
	s := screen(u)
	for _, want := range []string{"cofre · 3 itens", "› Amazon", "  github", "  Zoom", "↑↓ navegar · enter abrir · esc sair"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "S3nha") {
		t.Fatal("password shown in the list")
	}
}

func TestArrowsMoveSelectionWithinBounds(t *testing.T) {
	u, _, _ := openBox(t, vault("Amazon", "github", "Zoom"))
	u.Feed([]byte("\x1b[A"))
	if !strings.Contains(screen(u), "› Amazon") {
		t.Fatal("up moved past the first item")
	}
	u.Feed([]byte("\x1b[B\x1b[B\x1b[B\x1b[B"))
	if s := screen(u); !strings.Contains(s, "› Zoom") || strings.Contains(s, "› github") {
		t.Fatalf("down past the end:\n%s", s)
	}
	u.Feed([]byte("\x1bOA")) // application-mode arrow
	if !strings.Contains(screen(u), "› github") {
		t.Fatal("ESC O A not handled as up")
	}
}

func TestEnterShowsDetailsWithHiddenPassword(t *testing.T) {
	u, _, _ := openBox(t, vault("Amazon", "github"))
	u.Feed([]byte("\x1b[B\r"))
	s := screen(u)
	for _, want := range []string{"github", "usuário  ana@github", "senha    ••••••••", "espaço mostra/oculta a senha · esc volta"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "S3nha-github") || strings.Contains(s, "Amazon") {
		t.Fatalf("password or list shown:\n%s", s)
	}
	u.Feed([]byte(" "))
	if !strings.Contains(screen(u), "senha    S3nha-github") {
		t.Fatal("space did not reveal the password")
	}
	u.Feed([]byte(" "))
	if strings.Contains(screen(u), "S3nha-github") {
		t.Fatal("space did not hide the password again")
	}
}

func TestEscAndLeftReturnFromDetailsAndHideAgain(t *testing.T) {
	for _, back := range []string{"\x1b", "\x1b[D"} {
		u, _, done := openBox(t, vault("Amazon", "github"))
		u.Feed([]byte("\x1b[B\r "))
		u.Feed([]byte(back))
		s := screen(u)
		if !strings.Contains(s, "› github") || !strings.Contains(s, "  Amazon") {
			t.Fatalf("%q: not back to the list:\n%s", back, s)
		}
		select {
		case <-done:
			t.Fatalf("%q: box closed from details", back)
		default:
		}
		u.Feed([]byte("\r"))
		if strings.Contains(screen(u), "S3nha-github") {
			t.Fatalf("%q: password still revealed after reopening", back)
		}
	}
}

func TestEscClosesBoxBackIntoShield(t *testing.T) {
	for _, key := range []string{"\x1b", "\x03"} {
		u, c, done := openBox(t, vault("Amazon"))
		u.Feed([]byte(key))
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%q: Browse did not return", key)
		}
		c.t = c.t.Add(boxMorph / 2)
		mid := center(u.Render(80, 30))
		if strings.Contains(plain([]string{mid})[0], "Amazon") || !strings.Contains(mid, fmt.Sprintf("38;5;%dm", boxColor)) {
			t.Fatalf("%q: box not dissolving", key)
		}
		c.t = c.t.Add(boxMorph / 2)
		got := plain(u.Render(80, 30))[6:26]
		want := plain(shield(u.angle, 80, 20))
		for i := range want {
			if strings.TrimRight(got[i], " ") != strings.TrimRight(want[i], " ") {
				t.Fatalf("%q: row %d is not the shield after the morph", key, i)
			}
		}
		if strings.Contains(screen(u), "guardian> list") {
			t.Fatalf("%q: log shown instead of the shield", key)
		}
	}
}

func TestKeysGoToTheBoxNotTheInput(t *testing.T) {
	u, _, _ := openBox(t, vault("Amazon"))
	u.Feed([]byte("abc?"))
	if len(u.input) != 0 || u.help {
		t.Fatalf("input %q help %v", u.input, u.help)
	}
}

func TestLongListScrollsToKeepSelectionVisible(t *testing.T) {
	var names []string
	for i := range 30 {
		names = append(names, fmt.Sprintf("item%02d", i))
	}
	u, _, _ := openBox(t, vault(names...))
	for range 29 {
		u.Feed([]byte("\x1b[B"))
	}
	s := screen(u)
	if !strings.Contains(s, "› item29") || strings.Contains(s, "item00") {
		t.Fatalf("not scrolled:\n%s", s)
	}
	for range 29 {
		u.Feed([]byte("\x1b[A"))
	}
	if s := screen(u); !strings.Contains(s, "› item00") || strings.Contains(s, "item29") {
		t.Fatalf("not scrolled back:\n%s", s)
	}
}
