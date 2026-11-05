package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/guialves50/password-manager/src/cli"
)

const (
	Version  = "v0.1.0"
	maxInput = 4096
	reset    = "\x1b[0m"
	bold     = "\x1b[1m"
	dim      = "\x1b[38;5;245m"
	bar      = "\x1b[48;5;237m\x1b[38;5;252m"
)

var arrows = map[byte]string{'A': "up", 'B': "down", 'C': "right", 'D': "left"}

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

type result struct {
	text []byte
	err  error
}

type UI struct {
	mu       sync.Mutex
	server   string
	email    string
	log      []string
	partial  string
	input    []byte
	secret   bool
	waiting  chan result
	help     bool
	angle    float64
	esc      int
	pending  []byte
	leftover []byte
	clearAt  time.Time
	now      func() time.Time
	art      []string
	checkAt  time.Time

	browser            *browser
	form               *form
	boxAt, boxClosedAt time.Time
	closedRows         int
}

const (
	idleClear = 5 * time.Second
	checkShow = 3 * time.Second
)

func New(server string) *UI {
	return &UI{server: server, now: time.Now}
}

func (u *UI) Prompter() *cli.Prompter {
	return &cli.Prompter{
		In:         bufio.NewReader(readerFunc(u.readLine)),
		Out:        u,
		ReadSecret: func() ([]byte, error) { r := u.request(true); return r.text, r.err },
		OnSession: func(s *cli.Session) {
			u.mu.Lock()
			defer u.mu.Unlock()
			u.email, u.log, u.art = "", nil, nil
			if s == nil {
				u.checkAt = time.Time{}
				return
			}
			u.email = s.Email // keep a running ✓: a 2FA login plays it while the vault opens
		},
		ShowArt: func(lines []string) {
			u.mu.Lock()
			defer u.mu.Unlock()
			u.art = lines
		},
		Browse: u.browse,
		Pick:   u.pick,
		Show:   u.show,
		Box:    u.openForm,
		ShowCheck: func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			u.art, u.log, u.checkAt = nil, nil, u.now()
		},
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

func (u *UI) readLine(b []byte) (int, error) {
	if len(u.leftover) == 0 {
		r := u.request(false)
		if r.err != nil {
			return 0, r.err
		}
		u.leftover = append(r.text, '\n')
	}
	n := copy(b, u.leftover)
	u.leftover = u.leftover[n:]
	return n, nil
}

func (u *UI) request(secret bool) result {
	ch := make(chan result, 1)
	u.mu.Lock()
	u.secret, u.waiting = secret, ch
	u.clearAt = time.Time{}
	if !secret && u.atTop() {
		u.clearAt = u.now().Add(idleClear)
	}
	u.mu.Unlock()
	return <-ch
}

func (u *UI) Write(b []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	lines := strings.Split(u.partial+string(b), "\n")
	u.log = append(u.log, lines[:len(lines)-1]...)
	u.partial = lines[len(lines)-1]
	return len(b), nil
}

func (u *UI) Feed(b []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, c := range b {
		u.key(c)
	}
	// ponytail: a lone ESC is told apart from an arrow key by arriving alone in
	// one read; a sequence split across reads would close the box.
	if u.esc == 1 {
		u.esc = 0
		if u.browser != nil {
			u.browseKey("esc")
		}
	}
}

func (u *UI) key(c byte) {
	switch {
	case u.esc == 1 && (c == '[' || c == 'O'):
		u.esc = 2
		return
	case u.esc == 2:
		if c >= 0x40 && c <= 0x7e {
			u.esc = 0
			if k, ok := arrows[c]; ok && u.browser != nil {
				u.browseKey(k)
			}
		}
		return
	case u.esc == 1 && u.browser != nil:
		u.browseKey("esc")
	}
	u.esc = 0
	if u.browser != nil {
		switch c {
		case 0x1b:
			u.esc = 1
		case '\r', '\n':
			u.browseKey("enter")
		case ' ':
			u.browseKey("space")
		case 3, 4:
			u.browseKey("cancel")
		}
		return
	}
	if c != '?' {
		u.help = false
	}
	switch c {
	case 0x1b:
		u.esc = 1
	case '\r', '\n':
		u.submit()
	case 3, 4:
		u.clearInput()
		u.answer(result{err: io.EOF})
	case 12:
		u.log = nil
	case 21:
		u.clearInput()
	case 127, 8:
		if _, size := utf8.DecodeLastRune(u.input); size > 0 {
			clear(u.input[len(u.input)-size:])
			u.input = u.input[:len(u.input)-size]
		}
	default:
		if c == '?' && len(u.input) == 0 && !u.secret && u.form == nil {
			u.help = !u.help
			return
		}
		if c < 0x20 || len(u.input) >= maxInput {
			return
		}
		u.pending = append(u.pending, c)
		if utf8.FullRune(u.pending) {
			u.input = append(u.input, u.pending...)
			u.pending = u.pending[:0]
		}
	}
}

func (u *UI) submit() {
	if u.waiting == nil {
		return
	}
	text := append([]byte(nil), u.input...)
	if !u.secret {
		prefix := u.partial
		if prefix == "" {
			prefix = "› "
		}
		u.log = append(u.log, prefix+string(text))
		u.partial = ""
	}
	u.clearInput()
	u.answer(result{text: text})
}

func (u *UI) answer(r result) {
	if u.waiting != nil {
		u.waiting <- r
		u.waiting = nil
		u.clearAt = time.Time{}
	}
}

func (u *UI) atTop() bool {
	return u.partial == "" || strings.HasSuffix(u.partial, "> ")
}

func (u *UI) Tick() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.angle += 0.08
	if !u.clearAt.IsZero() && !u.now().Before(u.clearAt) {
		u.log, u.clearAt = nil, time.Time{}
	}
}

func (u *UI) clearInput() {
	clear(u.input)
	u.input = u.input[:0]
}

func visible(s string) int {
	return utf8.RuneCountInString(ansi.ReplaceAllString(s, ""))
}

func fit(s string, w int) string {
	if visible(s) <= w {
		return s + strings.Repeat(" ", w-visible(s))
	}
	r := []rune(ansi.ReplaceAllString(s, ""))
	return string(r[:max(0, w-1)]) + "…"
}

func wrap(lines []string, w int) []string {
	var out []string
	for _, l := range lines {
		r := []rune(l)
		for len(r) > w {
			out = append(out, string(r[:w]))
			r = r[w:]
		}
		out = append(out, string(r))
	}
	return out
}

func (u *UI) Render(w, h int) []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	w, h = max(w, 20), max(h, 12)
	screen := make([]string, h)
	who := dim + "não autenticado" + reset
	desc := "Suas senhas são cifradas neste dispositivo; o servidor só guarda blobs. Digite register, login ou recover."
	hint, status := "register, login, recover ou exit", "desconectado"
	if u.email != "" {
		who = u.email
		desc = "Cofre aberto. A sessão expira após 30 min sem uso."
		hint, status = "add, list, get [nome], delete [nome], 2fa ou exit", "cofre aberto"
	}
	screen[1] = "  " + dim + ">_ " + reset + bold + "Guardian" + reset + dim + " (" + Version + ")" + reset
	screen[2] = "     " + dim + u.server + " · " + reset + who
	screen[4] = "  " + dim + desc + reset

	top, bottomRow := 6, h-4
	if n := len(u.art); n > bottomRow-top && n <= bottomRow-1 {
		top = 1 // a QR code needs the header rows more than the header does
	}
	area := bottomRow - top
	var middle []string
	switch {
	case u.browser != nil && u.now().Sub(u.boxAt) < boxMorph:
		middle = morph(shieldRaster(u.angle, w, area), boxRaster(w, area, u.browser.rows()), float64(u.now().Sub(u.boxAt))/float64(boxMorph)).lines()
	case u.browser != nil:
		middle = u.browser.view(w, area)
	case u.form != nil && u.now().Sub(u.boxAt) < boxMorph:
		middle = morph(shieldRaster(u.angle, w, area), boxRaster(w, area, u.form.rows), float64(u.now().Sub(u.boxAt))/float64(boxMorph)).lines()
	case u.form != nil:
		middle = u.formView(w, area)
	case !u.boxClosedAt.IsZero() && u.now().Sub(u.boxClosedAt) < boxMorph:
		middle = morph(boxRaster(w, area, u.closedRows), shieldRaster(u.angle, w, area), float64(u.now().Sub(u.boxClosedAt))/float64(boxMorph)).lines()
	case u.help:
		middle = []string{"atalhos", "", "enter    envia", "ctrl+c   cancela o prompt atual (na tela inicial, sai)", "ctrl+l   limpa a tela", "ctrl+u   apaga a linha", "?        mostra ou esconde esta ajuda"}
		for i := range middle {
			middle[i] = "  " + middle[i]
		}
	case u.art != nil:
		middle = centered(u.art, w, area)
	case !u.checkAt.IsZero() && u.now().Sub(u.checkAt) < checkShow:
		middle = confirmation(u.now().Sub(u.checkAt), u.angle, w, area)
	case len(u.log) > 0:
		middle = wrap(u.log, w-4)
		middle = middle[max(0, len(middle)-area):]
		for i := range middle {
			middle[i] = "  " + middle[i]
		}
	default:
		middle = shield(u.angle, w, area)
	}
	for i, l := range middle[:min(len(middle), max(0, area))] {
		screen[top+i] = l
	}

	label := u.partial
	if u.waiting == nil || label == "" {
		label = "› "
	}
	text, after := []rune(string(u.input)), ""
	switch {
	case u.secret && u.waiting != nil:
		text, after = nil, dim+"(oculto)"
	case len(text) == 0 && u.atTop():
		after = dim + hint
	}
	if room := w - 3 - utf8.RuneCountInString(label); len(text) > room {
		text = append([]rune("…"), text[len(text)-max(0, room-1):]...)
	}
	screen[h-3] = bar + fit(" "+label+string(text)+"▏"+after+bar, w) + reset
	left, right := dim+"  ? atalhos", status+"  "+reset
	screen[h-2] = left + strings.Repeat(" ", max(1, w-visible(left)-visible(right))) + right
	for i := range screen {
		screen[i] = fit(screen[i], w) + reset
	}
	return screen
}

func centered(art []string, w, h int) []string {
	width := 0
	for _, l := range art {
		width = max(width, visible(l))
	}
	if len(art) > h || width > w {
		return []string{"", "  aumente o terminal para ver o QR Code", "", "  " + art[len(art)-1]}
	}
	out := make([]string, len(art))
	for i, l := range art {
		out[i] = strings.Repeat(" ", (w-width)/2) + l
	}
	return out
}

func Run(server string, app func(p *cli.Prompter)) error {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	restore := func() {
		fmt.Print("\x1b[?25h\x1b[?1049l")
		term.Restore(fd, state)
	}
	defer restore()
	fmt.Print("\x1b[?1049h\x1b[?25l")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)

	u := New(server)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			u.Feed(buf[:n])
			clear(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				restore()
				panic(r)
			}
		}()
		tick := time.NewTicker(66 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-sig:
				restore()
				os.Exit(1)
			case <-tick.C:
				w, h, err := term.GetSize(int(os.Stdout.Fd()))
				if err != nil {
					continue
				}
				u.Tick()
				var b strings.Builder
				for i, l := range u.Render(w, h) {
					fmt.Fprintf(&b, "\x1b[%d;1H%s", i+1, l)
				}
				os.Stdout.WriteString(b.String())
			}
		}
	}()
	app(u.Prompter())
	close(done)
	return nil
}
