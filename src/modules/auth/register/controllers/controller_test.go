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
	"github.com/guialves50/password-manager/src/modules/auth/register/services"
	"github.com/guialves50/password-manager/src/modules/user"
)

type fakeRepo struct {
	calls int
	err   error
}

func (f *fakeRepo) Create(context.Context, *user.User) error {
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

func command(repo *fakeRepo) cli.Command {
	return New(&services.Service{Repo: repo, Params: keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}})
}

func TestRegisterHappyPath(t *testing.T) {
	repo := &fakeRepo{}
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
		repo := &fakeRepo{err: c.repoErr}
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
