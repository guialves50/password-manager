package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/cli"
)

func uiAt() (*UI, *cli.Prompter, *clock) {
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	u := New("x")
	u.now = c.now
	return u, u.Prompter(), c
}

func asked(t *testing.T, u *UI, p *cli.Prompter, label string) chan string {
	t.Helper()
	ch := make(chan string, 1)
	go func() { s, _ := p.Line(label); ch <- s }()
	waitFor(t, u, func() bool { return u.waiting != nil && u.partial == label })
	return ch
}

func TestFormBoxFramesPrompts(t *testing.T) {
	u, p, c := uiAt()
	u.Write([]byte("guardian> add\n"))
	p.Box("novo item")
	c.t = c.t.Add(boxMorph / 2)
	if mid := center(u.Render(80, 30)); !strings.Contains(mid, fmt.Sprintf("38;5;%dm", boxColor)) || strings.Contains(plain([]string{mid})[0], "novo item") {
		t.Fatal("form box not forming from the shield")
	}
	c.t = c.t.Add(boxMorph / 2)
	ch := asked(t, u, p, "nome: ")
	u.Feed([]byte("Gmail\r"))
	if got := <-ch; got != "Gmail" {
		t.Fatalf("line %q", got)
	}
	asked(t, u, p, "usuário: ")
	u.Feed([]byte("ana"))
	s := screen(u)
	for _, want := range []string{"novo item", "nome: Gmail", "usuário: ana▏", "enter confirma"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "guardian> add") {
		t.Fatal("screen behind the box shown")
	}
}

func TestFormBoxHidesSecretInput(t *testing.T) {
	u, p, c := uiAt()
	p.Box("x")
	c.t = c.t.Add(boxMorph)
	go p.Secret("senha: ")
	waitFor(t, u, func() bool { return u.waiting != nil && u.secret })
	u.Feed([]byte("S3nha"))
	if s := screen(u); strings.Contains(s, "S3nha") || !strings.Contains(s, "senha: (oculto)") {
		t.Fatalf("secret in the box:\n%s", s)
	}
}

func TestFormBoxSuccessPlaysCheck(t *testing.T) {
	u, p, c := uiAt()
	u.Write([]byte("guardian> add\n"))
	done := p.Box("novo item")
	c.t = c.t.Add(boxMorph)
	u.Write([]byte("nome: Gmail\nitem salvo\n"))
	done(true)
	c.t = c.t.Add(500 * time.Millisecond)
	raw := center(u.Render(80, 30))
	if !strings.Contains(raw, checkColor) || strings.Contains(plain([]string{raw})[0], "item salvo") || len(u.log) != 0 {
		t.Fatalf("no check after saving: log %q", u.log)
	}
}

func TestFormBoxFailureDissolvesAndDropsTranscript(t *testing.T) {
	u, p, c := uiAt()
	u.Write([]byte("guardian> add\n"))
	done := p.Box("novo item")
	c.t = c.t.Add(boxMorph)
	u.Write([]byte("nome: Gmail\n"))
	done(false)
	u.Write([]byte("já existe um item com esse nome\n"))
	c.t = c.t.Add(boxMorph / 2)
	mid := center(u.Render(80, 30))
	if !strings.Contains(mid, fmt.Sprintf("38;5;%dm", boxColor)) || strings.Contains(plain([]string{mid})[0], "Gmail") {
		t.Fatal("box not dissolving")
	}
	c.t = c.t.Add(boxMorph / 2)
	if got := strings.Join(u.log, "|"); got != "guardian> add|já existe um item com esse nome" {
		t.Fatalf("log %q", got)
	}
	done(true) // closing twice is harmless
	if !u.checkAt.IsZero() {
		t.Fatal("second close played the check")
	}
}

func TestQuestionMarkTypesInsideForm(t *testing.T) {
	u, p, c := uiAt()
	p.Box("x")
	c.t = c.t.Add(boxMorph)
	asked(t, u, p, "notas: ")
	u.Feed([]byte("?"))
	if u.help || string(u.input) != "?" {
		t.Fatalf("help %v input %q", u.help, u.input)
	}
}

func TestPickReturnsChoiceOrCancel(t *testing.T) {
	for _, c := range []struct {
		keys string
		want int
		ok   bool
	}{{"\x1b[B\r", 1, true}, {"\x1b[B\x1b[C", 1, true}, {"\x1b", -1, false}, {"\x03", -1, false}} {
		u, p, clk := uiAt()
		got := make(chan [2]int, 1)
		go func() {
			i, ok := p.Pick(vault("Amazon", "Gmail"))
			b := 0
			if ok {
				b = 1
			}
			got <- [2]int{i, b}
		}()
		waitFor(t, u, func() bool { return u.browser != nil })
		clk.t = clk.t.Add(boxMorph)
		s := screen(u)
		if !strings.Contains(s, "escolha um item") || !strings.Contains(s, "↑↓ navegar · enter escolher · esc cancelar") {
			t.Fatalf("pick box:\n%s", s)
		}
		u.Feed([]byte(c.keys))
		r := <-got
		if r[0] != c.want || (r[1] == 1) != c.ok {
			t.Fatalf("%q: got %v", c.keys, r)
		}
	}
}

func TestShowOpensDetailsAndEscCloses(t *testing.T) {
	for _, key := range []string{"\x1b", "\x1b[D"} {
		u, p, c := uiAt()
		done := make(chan struct{})
		go func() { p.Show(vault("Gmail")[0]); close(done) }()
		waitFor(t, u, func() bool { return u.browser != nil })
		c.t = c.t.Add(boxMorph)
		s := screen(u)
		if !strings.Contains(s, "senha    ••••••••") || !strings.Contains(s, "esc fecha") || strings.Contains(s, "S3nha") {
			t.Fatalf("details:\n%s", s)
		}
		u.Feed([]byte(" "))
		if !strings.Contains(screen(u), "S3nha-Gmail") {
			t.Fatal("space did not reveal")
		}
		u.Feed([]byte(key))
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%q did not close the details", key)
		}
	}
}

func TestPickThenFormKeepsTheBox(t *testing.T) {
	u, p, c := uiAt()
	got := make(chan int, 1)
	go func() { i, _ := p.Pick(vault("Amazon", "Gmail")); got <- i }()
	waitFor(t, u, func() bool { return u.browser != nil })
	c.t = c.t.Add(boxMorph)
	u.Feed([]byte("\r"))
	<-got
	p.Box("remover item")
	if s := screen(u); !strings.Contains(s, "remover item") {
		t.Fatalf("form morphed again from the shield:\n%s", s)
	}
}
