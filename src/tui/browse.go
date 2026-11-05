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

// browser is the list box opened by `list`: a cursor over entries and, once
// one is opened, its fields with the secret hidden until revealed.
type browser struct {
	entries      []cli.Entry
	sel, top     int
	open, reveal bool
	done         chan struct{}
}

// browse blocks until the user closes the box (Esc or ctrl+c).
func (u *UI) browse(entries []cli.Entry) {
	b := &browser{entries: entries, done: make(chan struct{})}
	u.mu.Lock()
	u.browser, u.log, u.help, u.boxAt, u.boxClosedAt = b, nil, false, u.now(), time.Time{}
	u.mu.Unlock()
	<-b.done
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
		b.open, b.reveal = true, false
	case "space":
		b.reveal = b.open && !b.reveal
	case "left":
		b.open, b.reveal = false, false
	case "esc":
		if b.open {
			b.open, b.reveal = false, false
			return
		}
		u.closeBrowser()
	case "cancel":
		u.closeBrowser()
	}
}

func (u *UI) closeBrowser() {
	close(u.browser.done)
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
	x0, y0, bw, bh := box(w, h, b.rows())
	cells := boxRaster(w, h, b.rows()).cells()
	inner := bw - 4
	var text []string
	if b.open {
		e := b.entries[b.sel]
		text = append(text, bold+e.Title+reset, "")
		for _, f := range e.Fields {
			v := f.Value
			if f.Secret && !b.reveal {
				v = masked
			}
			text = append(text, dim+padLabel(f.Label)+reset+v)
		}
	} else {
		text = append(text, bold+"cofre"+reset+dim+" · "+count(len(b.entries))+reset, "")
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
	hint := "↑↓ navegar · enter abrir · esc sair"
	if b.open {
		hint = "espaço mostra/oculta a senha · esc volta"
	}
	for len(text) < bh-4 {
		text = append(text, "")
	}
	text = append(text[:bh-4], dim+hint+reset)
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
