package controllers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

// boxSpy records each box opened and closed, with the output written by then.
type boxSpy struct {
	events []string
	out    *bytes.Buffer
}

func (b *boxSpy) attach(p *cli.Prompter, out *bytes.Buffer) {
	b.out = out
	p.Box = func(title string) func(bool) {
		b.events = append(b.events, "open "+title+" @"+out.String())
		return func(ok bool) { b.events = append(b.events, fmt.Sprintf("close %v @%s", ok, out.String())) }
	}
}

func TestAddRunsInsideBoxAndClosesWithCheck(t *testing.T) {
	add := func(context.Context, *cli.Session, dto.Item) (int, error) { return 0, nil }
	gen := func(int) (string, error) { return "pw", nil }
	p, out := prompter("Gmail\nana\n\nurl\nnotas\n")
	spy := &boxSpy{}
	spy.attach(p, out)
	if err := NewAdd(add, gen)(context.Background(), p, session(), ""); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"open novo item @",
		"close true @nome: usuário: comprimento (20): url: notas: item salvo\n",
	}
	if strings.Join(spy.events, "|") != strings.Join(want, "|") {
		t.Fatalf("events %q", spy.events)
	}
}

func TestAddFailureDissolvesBoxThenReports(t *testing.T) {
	for _, c := range []struct {
		input string
		err   error
		want  string
	}{
		{"Gmail\nana\n\nurl\nnotas\n", vaulterrors.ErrNameTaken, "close false @nome: usuário: comprimento (20): url: notas: "},
		{"Gmail\n", nil, "close false @nome: usuário: "},
	} {
		add := func(context.Context, *cli.Session, dto.Item) (int, error) { return 0, c.err }
		gen := func(int) (string, error) { return "pw", nil }
		p, out := prompter(c.input)
		spy := &boxSpy{}
		spy.attach(p, out)
		err := NewAdd(add, gen)(context.Background(), p, session(), "")
		if err == nil || len(spy.events) != 2 || spy.events[1] != c.want {
			t.Fatalf("err %v events %q", err, spy.events)
		}
		if msg := strings.TrimPrefix(out.String(), strings.TrimPrefix(c.want, "close false @")); msg != vaulterrors.Message(err)+"\n" {
			t.Fatalf("message after close %q", msg)
		}
	}
}

func TestGetWithNameShowsEntryInTUI(t *testing.T) {
	it := dto.Item{Name: "Gmail", Username: "ana", Password: "pw"}
	get := func(context.Context, *cli.Session, string) (dto.Item, int, error) { return it, 0, nil }
	p, out := prompter("")
	var shown []cli.Entry
	p.Show = func(e cli.Entry) { shown = append(shown, e) }
	if err := NewGet(get, nil)(context.Background(), p, session(), "gmail"); err != nil {
		t.Fatal(err)
	}
	want := cli.Entry{Title: "Gmail", Fields: []cli.Field{{Label: "usuário", Value: "ana"}, {Label: "senha", Value: "pw", Secret: true}}}
	if len(shown) != 1 || fmt.Sprint(shown[0]) != fmt.Sprint(want) || out.Len() != 0 {
		t.Fatalf("shown %+v out %q", shown, out.String())
	}
}

func TestGetNotFoundInTUIPrintsMessage(t *testing.T) {
	get := func(context.Context, *cli.Session, string) (dto.Item, int, error) {
		return dto.Item{}, 0, vaulterrors.ErrNotFound
	}
	p, out := prompter("")
	p.Show = func(cli.Entry) { t.Fatal("shown a missing item") }
	NewGet(get, nil)(context.Background(), p, session(), "x")
	if out.String() != "item não encontrado\n" {
		t.Fatalf("out %q", out.String())
	}
}

func TestGetWithoutNameBrowsesInTUI(t *testing.T) {
	list := func(context.Context, *cli.Session) ([]dto.Item, int, error) { return named("Amazon", "Zoom"), 0, nil }
	p, _ := prompter("")
	var browsed [][]cli.Entry
	p.Browse = func(e []cli.Entry) { browsed = append(browsed, e) }
	if err := NewGet(nil, list)(context.Background(), p, session(), ""); err != nil {
		t.Fatal(err)
	}
	if len(browsed) != 1 || len(browsed[0]) != 2 || browsed[0][1].Title != "Zoom" {
		t.Fatalf("browsed %+v", browsed)
	}
}

func pickDelete(t *testing.T, items []dto.Item, pickIdx int, pickOK bool, input string) (*boxSpy, []string, *bytes.Buffer, error) {
	t.Helper()
	var dels []string
	list := func(context.Context, *cli.Session) ([]dto.Item, int, error) { return items, 0, nil }
	del := func(_ context.Context, _ *cli.Session, id string) error { dels = append(dels, id); return nil }
	find := func(context.Context, *cli.Session, string) (dto.Item, int, error) {
		t.Fatal("looked up by name without a name")
		return dto.Item{}, 0, nil
	}
	p, out := prompter(input)
	spy := &boxSpy{}
	spy.attach(p, out)
	p.Pick = func(e []cli.Entry) (int, bool) {
		if len(e) != len(items) {
			t.Fatalf("picked from %d entries", len(e))
		}
		return pickIdx, pickOK
	}
	err := NewDelete(find, list, del)(context.Background(), p, session(), "")
	return spy, dels, out, err
}

func TestDeleteWithoutNamePicksThenConfirmsInBox(t *testing.T) {
	items := []dto.Item{{ID: "a", Name: "Amazon"}, {ID: "z", Name: "Zoom"}}
	spy, dels, _, err := pickDelete(t, items, 1, true, "s\n")
	if err != nil || len(dels) != 1 || dels[0] != "z" {
		t.Fatalf("err %v dels %q", err, dels)
	}
	want := []string{"open remover item @", "close true @remover Zoom? (s/N) item removido\n"}
	if strings.Join(spy.events, "|") != strings.Join(want, "|") {
		t.Fatalf("events %q", spy.events)
	}
}

func TestDeletePickCancelledDoesNothing(t *testing.T) {
	spy, dels, out, err := pickDelete(t, []dto.Item{{ID: "a", Name: "Amazon"}}, -1, false, "")
	if err != nil || len(dels) != 0 || len(spy.events) != 0 || out.Len() != 0 {
		t.Fatalf("err %v dels %q events %q out %q", err, dels, spy.events, out.String())
	}
}

func TestDeleteDeclinedDissolvesBoxThenSaysCancelled(t *testing.T) {
	spy, dels, out, _ := pickDelete(t, []dto.Item{{ID: "a", Name: "Amazon"}}, 0, true, "n\n")
	if len(dels) != 0 || len(spy.events) != 2 || spy.events[1] != "close false @remover Amazon? (s/N) " {
		t.Fatalf("dels %q events %q", dels, spy.events)
	}
	if !strings.HasSuffix(out.String(), "remoção cancelada\n") {
		t.Fatalf("out %q", out.String())
	}
}

func TestDeleteWithoutNameEmptyVault(t *testing.T) {
	spy, _, out, err := pickDelete(t, nil, 0, true, "")
	if err != nil || out.String() != "cofre vazio\n" || len(spy.events) != 0 {
		t.Fatalf("err %v out %q events %q", err, out.String(), spy.events)
	}
}

func TestDeleteWithoutNameListError(t *testing.T) {
	boom := errors.New("db")
	list := func(context.Context, *cli.Session) ([]dto.Item, int, error) { return nil, 0, boom }
	p, out := prompter("")
	p.Pick = func([]cli.Entry) (int, bool) { t.Fatal("picked after a list error"); return 0, false }
	if err := NewDelete(nil, list, nil)(context.Background(), p, session(), ""); err != boom || out.String() != "erro interno\n" {
		t.Fatalf("err %v out %q", err, out.String())
	}
}

func TestDeleteByNameEOFDissolvesBox(t *testing.T) {
	s := session()
	cmd, calls := deleteCommand(t, s, dto.Item{ID: "a", Name: "Amazon"}, 0, nil, nil)
	p, out := prompter("")
	spy := &boxSpy{}
	spy.attach(p, out)
	if err := cmd(context.Background(), p, s, "amazon"); !errors.Is(err, io.EOF) {
		t.Fatalf("err %v", err)
	}
	if len(calls.dels) != 0 || len(spy.events) != 2 || !strings.HasPrefix(spy.events[1], "close false") {
		t.Fatalf("dels %q events %q", calls.dels, spy.events)
	}
}
