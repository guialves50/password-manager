package tui

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/guialves50/password-manager/src/cli"
)

const (
	boxMorph = 600 * time.Millisecond
	boxColor = 73
	selected = "\x1b[1m\x1b[38;5;77m"
	masked   = "••••••••"
)

// browser is the list box: a cursor over entries and, once one is opened,
// its fields with the secret hidden until revealed. pick makes Enter choose
// the entry instead of opening it; direct starts on one entry's details.
type browser struct {
	entries      []cli.Entry
	sel, top     int
	open, reveal bool
	pick, direct bool
	done         chan int // the picked index, or -1
}

// openBrowser blocks until the user closes the box.
func (u *UI) openBrowser(b *browser) int {
	b.done = make(chan int, 1)
	u.mu.Lock()
	u.browser, u.log, u.help = b, nil, false
	u.startBox()
	u.mu.Unlock()
	return <-b.done
}

func (u *UI) browse(entries []cli.Entry) { u.openBrowser(&browser{entries: entries}) }

func (u *UI) pick(entries []cli.Entry) (int, bool) {
	i := u.openBrowser(&browser{entries: entries, pick: true})
	return i, i >= 0
}

func (u *UI) show(e cli.Entry) {
	u.openBrowser(&browser{entries: []cli.Entry{e}, open: true, direct: true})
}

// startBox (mu held) morphs the box out of the shield, unless a box was just
// on screen: then the new one takes its place without a detour through the shield.
func (u *UI) startBox() {
	u.boxAt = u.now()
	if !u.boxClosedAt.IsZero() && u.boxAt.Sub(u.boxClosedAt) < boxMorph {
		u.boxAt = u.boxAt.Add(-boxMorph)
	}
	u.boxClosedAt = time.Time{}
}

func (u *UI) browseKey(k string) {
	b := u.browser
	switch k {
	case "up":
		if !b.open {
			b.sel = max(0, b.sel-1)
		}
	case "down":
		if !b.open {
			b.sel = min(len(b.entries)-1, b.sel+1)
		}
	case "enter", "right":
		if b.pick {
			u.closeBrowser(b.sel)
			return
		}
		b.open, b.reveal = true, false
	case "space":
		b.reveal = b.open && !b.reveal
	case "left", "esc":
		if b.open && !b.direct {
			b.open, b.reveal = false, false
			return
		}
		if k == "esc" || b.direct {
			u.closeBrowser(-1)
		}
	case "cancel":
		u.closeBrowser(-1)
	}
}

func (u *UI) closeBrowser(picked int) {
	u.browser.done <- picked
	u.closedRows = u.browser.rows()
	u.browser, u.boxClosedAt = nil, u.now()
}

// box returns the frame, in cells, of a box centered in a w×h area.
func box(w, h, rows int) (x0, y0, bw, bh int) {
	bw, bh = min(w-4, 60), min(h, max(10, rows+6))
	return (w - bw) / 2, (h - bh) / 2, bw, bh
}

func boxRaster(w, h, rows int) raster {
	r := newRaster(w, h)
	x0, y0, bw, bh := box(w, h, rows)
	left, right := x0*2+1, (x0+bw-1)*2
	top, bottom := y0*4+2, (y0+bh-1)*4+1
	for x := left; x <= right; x++ {
		r.set(x, top, boxColor)
		r.set(x, bottom, boxColor)
	}
	for y := top; y <= bottom; y++ {
		r.set(left, y, boxColor)
		r.set(right, y, boxColor)
	}
	return r
}

func (b *browser) rows() int {
	n := len(b.entries)
	for _, e := range b.entries {
		n = max(n, len(e.Fields))
	}
	return n
}

// view draws the box with the list or the opened entry inside it.
func (b *browser) view(w, h int) []string {
	_, _, _, bh := box(w, h, b.rows())
	var text []string
	hint := "↑↓ navegar · enter abrir · esc sair"
	switch {
	case b.open:
		e := b.entries[b.sel]
		text = append(text, bold+e.Title+reset, "")
		for _, f := range e.Fields {
			v := f.Value
			if f.Secret && !b.reveal {
				v = masked
			}
			text = append(text, dim+padLabel(f.Label)+reset+v)
		}
		hint = "espaço mostra/oculta a senha · esc volta"
		if b.direct {
			hint = "espaço mostra/oculta a senha · esc fecha"
		}
	default:
		title := bold + "cofre" + reset + dim + " · " + count(len(b.entries)) + reset
		if b.pick {
			title, hint = bold+"escolha um item"+reset, "↑↓ navegar · enter escolher · esc cancelar"
		}
		text = append(text, title, "")
		vis := bh - 6
		b.top = min(b.top, b.sel)
		b.top = max(b.top, b.sel-vis+1)
		for i := b.top; i < min(len(b.entries), b.top+vis); i++ {
			if i == b.sel {
				text = append(text, selected+"› "+b.entries[i].Title+reset)
			} else {
				text = append(text, "  "+b.entries[i].Title)
			}
		}
	}
	return drawBox(w, h, b.rows(), text, hint)
}

// drawBox lays text (title line, blank, body) and a hint inside the box frame.
// A body taller than the box keeps its last lines, so the newest stay visible.
func drawBox(w, h, rows int, text []string, hint string) []string {
	x0, y0, bw, bh := box(w, h, rows)
	cells := boxRaster(w, h, rows).cells()
	inner, room := bw-4, bh-4
	if len(text) > room {
		text = append(text[:2:2], text[len(text)-(room-2):]...)
	}
	for len(text) < room {
		text = append(text, "")
	}
	text = append(text, dim+hint+reset)
	for i, t := range text {
		row := cells[y0+1+i]
		row[x0+2] = fit(t, inner) + reset
		for c := x0 + 3; c < x0+2+inner; c++ {
			row[c] = ""
		}
	}
	out := make([]string, h)
	for i := range cells {
		out[i] = strings.Join(cells[i], "")
	}
	return out
}

func padLabel(l string) string {
	return l + strings.Repeat(" ", max(1, 9-utf8.RuneCountInString(l)))
}

func count(n int) string {
	if n == 1 {
		return "1 item"
	}
	return strconv.Itoa(n) + " itens"
}
