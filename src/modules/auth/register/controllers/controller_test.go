package controllers

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
	"github.com/guialves50/password-manager/src/modules/auth/register/services"
)

type fakeAPI struct {
	calls int
	err   error
}

func (f *fakeAPI) Register(context.Context, dto.Request) error {
	f.calls++
	return f.err
}

func prompter(line string, secrets ...string) (*cli.Prompter, *bytes.Buffer) {
	var out bytes.Buffer
	return &cli.Prompter{
		In:  bufio.NewReader(strings.NewReader(line)),
		Out: &out,
		ReadSecret: func() ([]byte, error) {
			if len(secrets) == 0 {
				return nil, io.EOF
			}
			s := secrets[0]
			secrets = secrets[1:]
			return []byte(s), nil
		},
	}, &out
}

func command(repo *fakeAPI) cli.Command {
	return New((&services.Service{API: repo, Params: keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}}).Register)
}

func TestRegisterHappyPath(t *testing.T) {
	repo := &fakeAPI{}
	p, out := prompter("alice@example.com\n", "SenhaForte1", "SenhaForte1")
	if err := command(repo)(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if repo.calls != 1 || !strings.Contains(s, "conta criada\n") {
		t.Fatalf("calls %d out %q", repo.calls, s)
	}
	if !regexp.MustCompile(`chave de recuperação: [A-Z2-7]{4}(-[A-Z2-7]{4}){7}\n`).MatchString(s) {
		t.Fatalf("no recovery key in %q", s)
	}
	if !strings.Contains(s, "não pode ser exibida novamente") {
		t.Fatalf("no warning in %q", s)
	}
	if strings.Contains(s, "SenhaForte1") {
		t.Fatalf("password leaked: %q", s)
	}
}

func TestRegisterErrors(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		secrets []string
		repoErr error
		want    string
	}{
		{"invalid email", "nope\n", []string{"SenhaForte1", "SenhaForte1"}, nil, "email inválido\n"},
		{"length", "a@example.com\n", []string{"Curta1", "Curta1"}, nil, "a senha mestra deve ter entre 8 e 128 caracteres\n"},
		{"case", "a@example.com\n", []string{"senhafraca", "senhafraca"}, nil, "a senha mestra deve conter letras maiúsculas e minúsculas\n"},
		{"mismatch", "a@example.com\n", []string{"SenhaForte1", "SenhaForte2"}, nil, "as senhas não conferem\n"},
		{"taken", "a@example.com\n", []string{"SenhaForte1", "SenhaForte1"}, autherrors.ErrEmailTaken, "email já cadastrado\n"},
		{"internal", "a@example.com\n", []string{"SenhaForte1", "SenhaForte1"}, errors.New("db down SenhaForte1"), "erro interno\n"},
		{"eof email", "", nil, nil, "operação cancelada\n"},
		{"eof password", "a@example.com\n", nil, nil, "operação cancelada\n"},
		{"eof confirm", "a@example.com\n", []string{"SenhaForte1"}, nil, "operação cancelada\n"},
	}
	for _, c := range cases {
		repo := &fakeAPI{err: c.repoErr}
		p, out := prompter(c.line, c.secrets...)
		err := command(repo)(context.Background(), p)
		s := out.String()
		if err == nil || !strings.HasSuffix(s, c.want) {
			t.Errorf("%s: err %v out %q", c.name, err, s)
		}
		if strings.Contains(s, "conta criada") || strings.Contains(s, "SenhaForte1") {
			t.Errorf("%s: unexpected output %q", c.name, s)
		}
		if c.repoErr == nil && repo.calls != 0 {
			t.Errorf("%s: repo called", c.name)
		}
	}
}

func TestRegisterBoxHoldsKeyUntilEnter(t *testing.T) {
	p, out := prompter("alice@example.com\n\n", "SenhaForte1", "SenhaForte1")
	var events []string
	p.Box = func(title string) func(bool) {
		events = append(events, "open "+title)
		return func(ok bool) {
			if ok {
				events = append(events, "close ok @"+out.String())
			} else {
				events = append(events, "close fail")
			}
		}
	}
	if err := command(&fakeAPI{})(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	key := regexp.MustCompile(`chave de recuperação: [A-Z2-7]{4}(-[A-Z2-7]{4}){7}\nguarde esta chave em local seguro: ela não pode ser exibida novamente\npressione enter quando tiver anotado $`)
	if len(events) != 2 || events[0] != "open criar conta" || !key.MatchString(events[1]) {
		t.Fatalf("events %q", events)
	}
}

func TestRegisterBoxFailure(t *testing.T) {
	p, out := prompter("alice@example.com\n", "SenhaForte1", "SenhaForte1")
	var closes []bool
	p.Box = func(string) func(bool) { return func(ok bool) { closes = append(closes, ok) } }
	if err := command(&fakeAPI{err: autherrors.ErrEmailTaken})(context.Background(), p); err == nil || len(closes) != 1 || closes[0] {
		t.Fatalf("err %v closes %v", err, closes)
	}
	if !strings.HasSuffix(out.String(), "email já cadastrado\n") {
		t.Fatalf("out %q", out.String())
	}
}
