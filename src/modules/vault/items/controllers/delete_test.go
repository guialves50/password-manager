package controllers

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type deleteCalls struct {
	finds []string
	dels  []string
}

func deleteCommand(t *testing.T, s *cli.Session, it dto.Item, skipped int, findErr, delErr error) (cli.SessionCommand, *deleteCalls) {
	calls := &deleteCalls{}
	find := func(_ context.Context, cs *cli.Session, name string) (dto.Item, int, error) {
		if cs != s {
			t.Errorf("find session %v", cs)
		}
		calls.finds = append(calls.finds, name)
		return it, skipped, findErr
	}
	del := func(_ context.Context, cs *cli.Session, id string) error {
		if cs != s {
			t.Errorf("del session %v", cs)
		}
		calls.dels = append(calls.dels, id)
		return delErr
	}
	return NewDelete(find, nil, del), calls
}

func TestDeleteConfirmed(t *testing.T) {
	for _, answer := range []string{"s\n", "  s  \n", "s"} {
		s := session()
		cmd, calls := deleteCommand(t, s, dto.Item{ID: "id-1", Name: "Gmail", Password: "S3nhaDoGmail"}, 0, nil, nil)
		p, out := prompter(answer)
		if err := cmd(context.Background(), p, s, "gmail"); err != nil {
			t.Errorf("%q: err %v", answer, err)
		}
		if len(calls.finds) != 1 || calls.finds[0] != "gmail" || len(calls.dels) != 1 || calls.dels[0] != "id-1" {
			t.Errorf("%q: calls %+v", answer, calls)
		}
		if o := out.String(); o != "remover Gmail? (s/N) item removido\n" {
			t.Errorf("%q: out %q", answer, o)
		}
	}
}

func TestDeleteOtherAnswersCancel(t *testing.T) {
	for _, answer := range []string{"n\n", "\n", "sim\n", "S\n", "N\n"} {
		s := session()
		cmd, calls := deleteCommand(t, s, dto.Item{ID: "id-1", Name: "Gmail", Password: "p"}, 0, nil, nil)
		p, out := prompter(answer)
		if err := cmd(context.Background(), p, s, "gmail"); err != nil || len(calls.dels) != 0 {
			t.Errorf("%q: err %v dels %v", answer, err, calls.dels)
		}
		if o := out.String(); o != "remover Gmail? (s/N) remoção cancelada\n" {
			t.Errorf("%q: out %q", answer, o)
		}
	}
}

func TestDeleteNotFoundDoesNotAsk(t *testing.T) {
	s := session()
	cmd, calls := deleteCommand(t, s, dto.Item{}, 0, vaulterrors.ErrNotFound, nil)
	p, out := prompter("s\n")
	if err := cmd(context.Background(), p, s, "gmail"); err != vaulterrors.ErrNotFound || len(calls.dels) != 0 {
		t.Fatalf("err %v dels %v", err, calls.dels)
	}
	if o := out.String(); o != "item não encontrado\n" {
		t.Fatalf("out %q", o)
	}
}

func TestDeleteEOFAtConfirmationCancels(t *testing.T) {
	s := session()
	cmd, calls := deleteCommand(t, s, dto.Item{ID: "id-1", Name: "Gmail", Password: "p"}, 0, nil, nil)
	p, out := prompter("")
	if err := cmd(context.Background(), p, s, "gmail"); !errors.Is(err, io.EOF) || len(calls.dels) != 0 {
		t.Fatalf("err %v dels %v", err, calls.dels)
	}
	if o := out.String(); o != "remover Gmail? (s/N) operação cancelada\n" {
		t.Fatalf("out %q", o)
	}
}

func TestDeleteErrors(t *testing.T) {
	boom := errors.New("db down")
	cases := []struct {
		name    string
		findErr error
		delErr  error
		want    string
	}{
		{"find internal", boom, nil, "erro interno\n"},
		{"del internal", nil, boom, "remover Gmail? (s/N) erro interno\n"},
		{"del not found", nil, vaulterrors.ErrNotFound, "remover Gmail? (s/N) item não encontrado\n"},
	}
	for _, c := range cases {
		s := session()
		cmd, _ := deleteCommand(t, s, dto.Item{ID: "id-1", Name: "Gmail", Password: "p"}, 0, c.findErr, c.delErr)
		p, out := prompter("s\n")
		want := c.findErr
		if want == nil {
			want = c.delErr
		}
		if err := cmd(context.Background(), p, s, "gmail"); err != want {
			t.Errorf("%s: err %v", c.name, err)
		}
		if o := out.String(); o != c.want {
			t.Errorf("%s: out %q", c.name, o)
		}
	}
}

func TestDeleteSkippedWarning(t *testing.T) {
	warn := "aviso: 1 item(ns) ignorado(s) por falha de integridade\n"
	cases := []struct {
		name    string
		findErr error
		answer  string
		want    string
	}{
		{"removed", nil, "s\n", "remover Gmail? (s/N) item removido\n" + warn},
		{"cancelled", nil, "n\n", "remover Gmail? (s/N) remoção cancelada\n" + warn},
		{"not found", vaulterrors.ErrNotFound, "s\n", "item não encontrado\n" + warn},
	}
	for _, c := range cases {
		s := session()
		cmd, _ := deleteCommand(t, s, dto.Item{ID: "id-1", Name: "Gmail", Password: "p"}, 1, c.findErr, nil)
		p, out := prompter(c.answer)
		if err := cmd(context.Background(), p, s, "gmail"); err != c.findErr {
			t.Errorf("%s: err %v", c.name, err)
		}
		if o := out.String(); o != c.want {
			t.Errorf("%s: out %q", c.name, o)
		}
	}
}

func TestDeleteWithoutNamePrintsUsage(t *testing.T) {
	s := session()
	cmd, calls := deleteCommand(t, s, dto.Item{}, 0, nil, nil)
	p, out := prompter("s\n")
	if err := cmd(context.Background(), p, s, ""); err != nil || len(calls.finds) != 0 || len(calls.dels) != 0 {
		t.Fatalf("err %v calls %+v", err, calls)
	}
	if o := out.String(); o != "uso: delete <nome>\n" {
		t.Fatalf("out %q", o)
	}
}
