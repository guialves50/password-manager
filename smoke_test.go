//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/user"
	"gorm.io/gorm"
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
	connect := func() (*gorm.DB, error) { return db, nil }
	email := fmt.Sprintf("smoke+%d@test.local", time.Now().UnixNano())
	keyRe := regexp.MustCompile(`chave de recuperação: ([A-Z2-7]{4}(?:-[A-Z2-7]{4}){7})\n`)

	step := func(name string, want int, wantOut string, args []string, lines string, secrets ...string) string {
		t.Helper()
		p, out := fakePrompter(lines, secrets...)
		if code := start(connect, args, p, io.Discard); code != want || !strings.Contains(out.String(), wantOut) {
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

	u, err := user.NewRepository(db).FindByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("reload: %+v, %v", u, err)
	}
	if u.KDFTime != 3 || u.KDFMemoryKiB != 65536 || u.KDFThreads != 4 {
		t.Fatalf("kdf params %d/%d/%d", u.KDFTime, u.KDFMemoryKiB, u.KDFThreads)
	}
	if len(u.MasterSalt) != 16 || len(u.RecoverySalt) != 16 || len(u.MasterWrappedKey) != 60 || len(u.RecoveryWrappedKey) != 60 {
		t.Fatalf("lens %d/%d/%d/%d", len(u.MasterSalt), len(u.RecoverySalt), len(u.MasterWrappedKey), len(u.RecoveryWrappedKey))
	}

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

	item := "gmail\nalice@gmail.com\nhttps://mail.google.com\nconta pessoal\n"
	added := "pm> nome: usuário: senha: \nurl: notas: item salvo\n"
	want := "email: senha mestra: \n" + added +
		"pm> gmail\n" +
		"pm> nome: gmail\nusuário: alice@gmail.com\nsenha: S3nhaDoGmail\nurl: https://mail.google.com\nnotas: conta pessoal\n" +
		"pm> remover gmail? (s/N) item removido\n" +
		"pm> cofre vazio\n" +
		"pm> "
	if out := step("vault", 0, want, []string{"login"}, email+"\nadd\n"+item+"list\nget GMAIL\ndelete gmail\ns\nlist\nexit\n", "SenhaOutra1", "S3nhaDoGmail"); out != want {
		t.Fatalf("vault: out %q", out)
	}

	want = "email: senha mestra: \n" + added + "pm> "
	if out := step("vault add again", 0, want, []string{"login"}, email+"\nadd\n"+item+"exit\n", "SenhaOutra1", "S3nhaDoGmail"); out != want {
		t.Fatalf("vault add again: out %q", out)
	}

	rows, err := db.Raw("SELECT * FROM vault_items").Rows()
	if err != nil {
		t.Fatal(err)
	}
	if cols, err := rows.Columns(); err != nil || strings.Join(cols, ",") != "id,user_id,blob,created_at" {
		t.Fatalf("columns %v, %v", cols, err)
	}
	var dump bytes.Buffer
	mine := 0
	for rows.Next() {
		var id string
		var userID uint64
		var blob []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &userID, &blob, &createdAt); err != nil {
			t.Fatal(err)
		}
		if userID == u.ID {
			mine++
		}
		fmt.Fprintf(&dump, "%s|%d|%s|%s\n", id, userID, blob, createdAt)
	}
	if err := rows.Close(); err != nil || mine != 1 {
		t.Fatalf("rows for user: %d, %v", mine, err)
	}
	for _, field := range []string{"gmail", "alice@gmail.com", "S3nhaDoGmail", "https://mail.google.com", "conta pessoal"} {
		if bytes.Contains(dump.Bytes(), []byte(field)) {
			t.Fatalf("vault_items dump contains %q in clear", field)
		}
	}

	email2 := fmt.Sprintf("smoke2+%d@test.local", time.Now().UnixNano())
	step("register second", 0, "conta criada\n", []string{"register"}, email2+"\n", "SenhaSegunda1", "SenhaSegunda1")
	u2, err := user.NewRepository(db).FindByEmail(context.Background(), email2)
	if err != nil || u2 == nil {
		t.Fatalf("second user: %+v, %v", u2, err)
	}
	res := db.Exec("INSERT INTO vault_items (id, user_id, blob, created_at) SELECT ?, ?, blob, created_at FROM vault_items WHERE user_id = ?", strings.Repeat("ab", 16), u2.ID, u.ID)
	if res.Error != nil || res.RowsAffected != 1 {
		t.Fatalf("copy blob: %d, %v", res.RowsAffected, res.Error)
	}
	want = "email: senha mestra: \npm> cofre vazio\naviso: 1 item(ns) ignorado(s) por falha de integridade\npm> "
	if out := step("moved blob", 0, want, []string{"login"}, email2+"\nlist\nexit\n", "SenhaSegunda1"); out != want {
		t.Fatalf("moved blob: out %q", out)
	}
}
