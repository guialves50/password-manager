//go:build integration

package main

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/guialves50/password-manager/src/database"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/server"
)

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

func TestSessionExpiresMidShell(t *testing.T) {
	var skew atomic.Int64
	now := func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	srv := httptest.NewServer(server.New(database.TestTx(t), server.Config{Secret: bytes.Repeat([]byte{1}, 32), AuthParams: keys.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}, Now: now}))
	defer srv.Close()
	t.Setenv("PM_SERVER", srv.URL)
	email := fmt.Sprintf("expire+%d@test.local", time.Now().UnixNano())

	p, _ := fakePrompter(email+"\n", "SenhaForte1", "SenhaForte1")
	if code := start([]string{"register"}, p, io.Discard); code != 0 {
		t.Fatalf("register: %d", code)
	}

	p, out := fakePrompter("", "SenhaForte1")
	afterLogin := strings.NewReader("list\nlist\n")
	moved := false
	p.In.Reset(io.MultiReader(strings.NewReader(email+"\n"), readerFunc(func(b []byte) (int, error) {
		if !moved {
			skew.Store(int64(31 * time.Minute))
			moved = true
		}
		return afterLogin.Read(b)
	})))
	code := start([]string{"login"}, p, io.Discard)
	want := "email: senha mestra: \nguardian> sessão expirada, faça login novamente\n"
	if code != 0 || out.String() != want {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

func TestServeFailsOnOldFormatDatabase(t *testing.T) {
	dsn := cmp.Or(os.Getenv("DATABASE_URL"), "postgres://postgres:postgres@localhost:5433/password_manager?sslmode=disable")
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("pm_old_%d", time.Now().UnixNano())
	if err := admin.Exec("CREATE DATABASE " + name).Error; err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(dsn, "/password_manager?", "/"+name+"?", 1)
	t.Cleanup(func() {
		admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
	})

	db, err := gorm.Open(postgres.Open(old), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Exec(`CREATE TABLE users (
		id bigserial PRIMARY KEY, email varchar(254) NOT NULL UNIQUE CHECK (email = lower(email)),
		kdf_time bigint NOT NULL, kdf_memory_ki_b bigint NOT NULL, kdf_threads smallint NOT NULL,
		master_salt bytea NOT NULL, master_wrapped_key bytea NOT NULL,
		recovery_salt bytea NOT NULL, recovery_wrapped_key bytea NOT NULL,
		failed_attempts bigint NOT NULL DEFAULT 0, locked_until timestamptz,
		created_at timestamptz, updated_at timestamptz);
		INSERT INTO users (email, kdf_time, kdf_memory_ki_b, kdf_threads, master_salt, master_wrapped_key, recovery_salt, recovery_wrapped_key)
		VALUES ('old@test.local', 3, 65536, 4, '\x00', '\x00', '\x00', '\x00')`).Error
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}

	t.Setenv("DATABASE_URL", old)
	t.Setenv("PM_ADDR", "256.0.0.1:0")
	t.Setenv("PM_SERVER_SECRET", strings.Repeat("ab", 32))
	var stdout, stderr bytes.Buffer
	if code := serve(database.Connect, &stdout, &stderr); code != 1 || stderr.String() != "não foi possível preparar o banco de dados\n" {
		t.Fatalf("code %d stderr %q stdout %q", code, stderr.String(), stdout.String())
	}
}
