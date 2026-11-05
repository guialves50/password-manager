package tui

const formRows = 5

// form is a box that frames the prompts of a command (add, delete) while it runs.
type form struct {
	title       string
	start, rows int // log lines before start belong to the screen behind the box
}

// openForm draws the next prompts inside a box; the returned func closes it,
// playing the ✓ when ok or dissolving the box back into the shield otherwise.
func (u *UI) openForm(title string) func(ok bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	rows := formRows
	if !u.boxClosedAt.IsZero() && u.now().Sub(u.boxClosedAt) < boxMorph {
		rows = u.closedRows // replacing a pick list: keep its size
	}
	f := &form{title: title, start: len(u.log), rows: rows}
	u.form, u.help = f, false
	u.startBox()
	return func(ok bool) {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.form != f {
			return
		}
		u.form, u.closedRows = nil, f.rows
		u.log = u.log[:min(f.start, len(u.log))]
		if ok {
			u.log, u.checkAt = nil, u.now()
		} else {
			u.boxClosedAt = u.now()
		}
	}
}

func (u *UI) formView(w, h int) []string {
	f := u.form
	text := append([]string{bold + f.title + reset, ""}, u.log[min(f.start, len(u.log)):]...)
	if u.partial != "" {
		in := string(u.input)
		if u.secret {
			in = dim + "(oculto)"
		}
		text = append(text, u.partial+selected+in+"▏"+reset)
	}
	return drawBox(w, h, f.rows, text, "enter confirma")
}
