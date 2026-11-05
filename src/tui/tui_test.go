package tui

import (
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/cli"
)

func plain(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = ansi.ReplaceAllString(l, "")
	}
	return out
}

func columns(lines []string) (lo, hi int) {
	lo, hi = math.MaxInt, -1
	for _, l := range plain(lines) {
		for i, r := range []rune(l) {
			if r != ' ' {
				lo, hi = min(lo, i), max(hi, i)
			}
		}
	}
	return lo, hi
}

func TestShieldFillsWidthAndRotates(t *testing.T) {
	front := shield(0, 80, 20)
	for i, l := range plain(front) {
		if n := len([]rune(l)); n != 80 {
			t.Fatalf("row %d width %d", i, n)
		}
	}
	lo, hi := columns(front)
	if lo < 0 || 79-hi < lo-1 || 79-hi > lo+1 {
		t.Fatalf("front not centered: %d..%d", lo, hi)
	}
	edgeLo, edgeHi := columns(shield(math.Pi/2, 80, 20))
	if edgeHi-edgeLo > 6 || edgeHi-edgeLo >= hi-lo {
		t.Fatalf("edge-on width %d, front %d", edgeHi-edgeLo, hi-lo)
	}
}

func waitFor(t *testing.T, u *UI, cond func() bool) {
	t.Helper()
	for range 200 {
		u.mu.Lock()
		ok := cond()
		u.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout")
}

func line(t *testing.T, u *UI, p *cli.Prompter, label, keys string) (string, error) {
	t.Helper()
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() { s, err := p.Line(label); ch <- res{s, err} }()
	waitFor(t, u, func() bool { return u.waiting != nil })
	u.Feed([]byte(keys))
	r := <-ch
	return r.s, r.err
}

func TestLineEchoesIntoLog(t *testing.T) {
	u := New("http://127.0.0.1:8080")
	p := u.Prompter()
	got, err := line(t, u, p, "nome: ", "gmaix\x7fl\x1b[D\r")
	if err != nil || got != "gmail" {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := line(t, u, p, "", "list\r"); got != "list" {
		t.Fatalf("home %q", got)
	}
	if strings.Join(u.log, "|") != "nome: gmail|› list" {
		t.Fatalf("log %q", u.log)
	}
}

func TestCtrlCCancelsPrompt(t *testing.T) {
	u := New("x")
	p := u.Prompter()
	if _, err := line(t, u, p, "nome: ", "abc\x03"); !errors.Is(err, io.EOF) {
		t.Fatalf("err %v", err)
	}
	if len(u.input) != 0 {
		t.Fatalf("input kept %q", u.input)
	}
}

func TestSecretNeverShown(t *testing.T) {
	u := New("x")
	p := u.Prompter()
	ch := make(chan []byte, 1)
	go func() { b, _ := p.Secret("senha mestra: "); ch <- b }()
	waitFor(t, u, func() bool { return u.waiting != nil })
	u.Feed([]byte("Segredo123"))
	typed := append([]byte(nil), u.input...)
	screen := strings.Join(plain(u.Render(100, 30)), "\n")
	if strings.Contains(screen, "Segredo") || !strings.Contains(screen, "senha mestra: ▏(oculto)") {
		t.Fatalf("screen leaks or misses prompt:\n%s", screen)
	}
	backing := u.input[:cap(u.input)]
	u.Feed([]byte("\r"))
	if got := <-ch; string(got) != "Segredo123" || string(typed) != "Segredo123" {
		t.Fatalf("secret %q", got)
	}
	for _, b := range backing[:len(typed)] {
		if b != 0 {
			t.Fatal("input buffer not zeroed")
		}
	}
	if strings.Contains(strings.Join(u.log, "\n"), "Segredo") || u.log[0] != "senha mestra: " {
		t.Fatalf("log %q", u.log)
	}
}

func TestRenderLayout(t *testing.T) {
	u := New("http://127.0.0.1:8080")
	screen := plain(u.Render(100, 30))
	if len(screen) != 30 {
		t.Fatalf("rows %d", len(screen))
	}
	for i, l := range screen {
		if n := len([]rune(l)); n != 100 {
			t.Fatalf("row %d width %d: %q", i, n, l)
		}
	}
	if !strings.Contains(screen[1], ">_ Guardian ("+Version+")") || !strings.Contains(screen[2], "http://127.0.0.1:8080 · não autenticado") {
		t.Fatalf("header %q / %q", screen[1], screen[2])
	}
	if !strings.Contains(screen[27], "› ▏register, login, recover ou exit") || !strings.Contains(screen[28], "? atalhos") || !strings.HasSuffix(strings.TrimRight(screen[28], " "), "desconectado") {
		t.Fatalf("bottom %q / %q", screen[27], screen[28])
	}
	if lo, hi := columns(screen[6:26]); hi-lo < 20 {
		t.Fatal("shield missing on empty log")
	}

	u.Prompter().OnSession(&cli.Session{Email: "alice@example.com"})
	u.Write([]byte("item salvo\nguardian> "))
	u.waiting = make(chan result, 1)
	screen = plain(u.Render(100, 30))
	if !strings.Contains(screen[2], "· alice@example.com") || !strings.HasSuffix(strings.TrimRight(screen[28], " "), "cofre aberto") {
		t.Fatalf("session header/footer %q / %q", screen[2], screen[28])
	}
	if strings.TrimSpace(screen[6]) != "item salvo" || !strings.Contains(screen[27], "guardian> ▏add, list") {
		t.Fatalf("log/prompt %q / %q", screen[6], screen[27])
	}

	u.Feed([]byte("\x0c"))
	if lo, hi := columns(plain(u.Render(100, 30))[6:26]); hi-lo < 20 {
		t.Fatal("ctrl+l did not bring the shield back")
	}
	u.Feed([]byte("?"))
	if !strings.Contains(strings.Join(plain(u.Render(100, 30)), "\n"), "ctrl+l   limpa a tela") {
		t.Fatal("help not shown")
	}
}

func TestRenderTinyTerminal(t *testing.T) {
	u := New("http://127.0.0.1:8080")
	for _, size := range [][2]int{{1, 1}, {20, 12}, {30, 14}} {
		for _, prep := range []func(){func() {}, func() { u.Feed([]byte("?")) }, func() { u.help = false; u.Write([]byte(strings.Repeat("linha\n", 50))) }} {
			prep()
			screen := plain(u.Render(size[0], size[1]))
			if len(screen) != max(size[1], 12) || len([]rune(screen[0])) != max(size[0], 20) {
				t.Fatalf("%v: %d rows", size, len(screen))
			}
		}
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func pendingLine(t *testing.T, u *UI, p *cli.Prompter, label string) chan string {
	t.Helper()
	ch := make(chan string, 1)
	go func() { s, _ := p.Line(label); ch <- s }()
	waitFor(t, u, func() bool { return u.waiting != nil })
	return ch
}

func TestLoginClearsToShield(t *testing.T) {
	u := New("x")
	p := u.Prompter()
	u.Write([]byte("› login\nemail: a@b.com\nsenha mestra: \n"))
	p.OnSession(&cli.Session{Email: "a@b.com"})
	if len(u.log) != 0 {
		t.Fatalf("log after login %q", u.log)
	}
	u.Write([]byte("item salvo\n"))
	p.OnSession(nil)
	if len(u.log) != 0 {
		t.Fatalf("log after logout %q", u.log)
	}
}

func TestIdleTopPromptClearsAfterFiveSeconds(t *testing.T) {
	for _, label := range []string{"", "guardian> "} {
		c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
		u := New("x")
		u.now = c.now
		p := u.Prompter()
		u.Write([]byte("cofre vazio\n"))
		done := pendingLine(t, u, p, label)
		u.Feed([]byte("li"))
		c.t = c.t.Add(idleClear - time.Millisecond)
		u.Tick()
		if len(u.log) != 1 {
			t.Fatalf("%q: cleared early: %q", label, u.log)
		}
		c.t = c.t.Add(time.Millisecond)
		u.Tick()
		if len(u.log) != 0 || string(u.input) != "li" || u.partial != label {
			t.Fatalf("%q: log %q input %q partial %q", label, u.log, u.input, u.partial)
		}
		u.Feed([]byte("st\r"))
		if got := <-done; got != "list" {
			t.Fatalf("%q: line %q", label, got)
		}
	}
}

func TestMidCommandPromptNeverClears(t *testing.T) {
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	u := New("x")
	u.now = c.now
	p := u.Prompter()
	u.Write([]byte("guardian> add\n"))
	done := pendingLine(t, u, p, "nome: ")
	c.t = c.t.Add(time.Hour)
	u.Tick()
	if len(u.log) != 1 {
		t.Fatalf("cleared mid-command: %q", u.log)
	}
	u.Feed([]byte("gmail\r"))
	<-done

	secret := make(chan struct{})
	go func() { p.Secret("senha mestra: "); close(secret) }()
	waitFor(t, u, func() bool { return u.waiting != nil })
	c.t = c.t.Add(time.Hour)
	u.Tick()
	if len(u.log) != 2 {
		t.Fatalf("cleared at secret prompt: %q", u.log)
	}
	u.Feed([]byte("\r"))
	<-secret
}

func TestTimerRestartsAfterEachCommand(t *testing.T) {
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	u := New("x")
	u.now = c.now
	p := u.Prompter()
	done := pendingLine(t, u, p, "guardian> ")
	c.t = c.t.Add(4 * time.Second)
	u.Feed([]byte("list\r"))
	<-done
	u.Tick()
	u.Write([]byte("gmail\n"))
	c.t = c.t.Add(2 * time.Second)
	u.Tick()
	if len(u.log) != 2 {
		t.Fatalf("cleared while command ran: %q", u.log)
	}
	done = pendingLine(t, u, p, "guardian> ")
	c.t = c.t.Add(4 * time.Second)
	u.Tick()
	if len(u.log) != 2 {
		t.Fatalf("old deadline reused: %q", u.log)
	}
	c.t = c.t.Add(time.Second)
	u.Tick()
	if len(u.log) != 0 {
		t.Fatalf("not cleared: %q", u.log)
	}
	u.Feed([]byte("\x03"))
	<-done
}
