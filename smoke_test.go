//go:build integration

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"maps"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/database"
	login "github.com/guialves50/password-manager/src/modules/auth/login/router"
	recover "github.com/guialves50/password-manager/src/modules/auth/recover/router"
	register "github.com/guialves50/password-manager/src/modules/auth/register/router"
)

func fakePrompter(lines string, secrets ...string) (*cli.Prompter, *bytes.Buffer) {
	var out bytes.Buffer
	return &cli.Prompter{
		In:  bufio.NewReader(strings.NewReader(lines)),
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

func TestSmokeEndToEnd(t *testing.T) {
	db := database.TestTx(t)
	routes := register.Routes(db)
	maps.Copy(routes, login.Routes(db))
	maps.Copy(routes, recover.Routes(db))
	email := fmt.Sprintf("smoke+%d@test.local", time.Now().UnixNano())
	keyRe := regexp.MustCompile(`chave de recuperação: ([A-Z2-7]{4}(?:-[A-Z2-7]{4}){7})\n`)

	step := func(name string, want int, wantOut string, args []string, lines string, secrets ...string) string {
		t.Helper()
		p, out := fakePrompter(lines, secrets...)
		if code := run(args, routes, p, io.Discard); code != want || !strings.Contains(out.String(), wantOut) {
			t.Fatalf("%s: code %d out %q", name, code, out.String())
		}
		return out.String()
	}

	out := step("register", 0, "conta criada\n", []string{"register"}, email+"\n", "SenhaAntiga1", "SenhaAntiga1")
	m := keyRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no recovery key in %q", out)
	}
	oldKey := m[1]

	step("login", 0, "pm> ", []string{"login"}, email+"\nexit\n", "SenhaAntiga1")

	out = step("recover", 0, "senha mestra redefinida\n", []string{"recover"}, email+"\n", strings.ToLower(oldKey), "SenhaNova1", "SenhaNova1")
	m = keyRe.FindStringSubmatch(out)
	if m == nil || m[1] == oldKey {
		t.Fatalf("no new recovery key in %q", out)
	}

	step("login new", 0, "pm> ", []string{"login"}, email+"\nexit\n", "SenhaNova1")
	step("login old", 1, "email ou senha mestra inválidos\n", []string{"login"}, email+"\n", "SenhaAntiga1")
	step("recover old key", 1, "email ou chave de recuperação inválidos\n", []string{"recover"}, email+"\n", oldKey, "SenhaOutra1", "SenhaOutra1")
	step("recover new key", 0, "senha mestra redefinida\n", []string{"recover"}, email+"\n", m[1], "SenhaOutra1", "SenhaOutra1")
}
