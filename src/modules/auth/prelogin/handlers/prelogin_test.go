package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

type fakeUsers struct {
	u   *user.User
	err error
}

func (f *fakeUsers) FindByEmail(_ context.Context, email string) (*user.User, error) {
	if f.err != nil || f.u == nil || f.u.Email != email {
		return nil, f.err
	}
	return f.u, nil
}

var alice = &user.User{
	Email: "alice@example.com", KDFTime: 2, KDFMemoryKiB: 1024, KDFThreads: 1,
	MasterSalt: bytes.Repeat([]byte{1}, 16), RecoverySalt: bytes.Repeat([]byte{2}, 16),
}

func post(t *testing.T, h http.HandlerFunc, body string) (*httptest.ResponseRecorder, map[string]any, dto.Response) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/prelogin", strings.NewReader(body)))
	var raw map[string]any
	var resp dto.Response
	json.Unmarshal(rec.Body.Bytes(), &raw)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, raw, resp
}

func keysOf(m map[string]any) []string {
	var out []string
	for k, v := range m {
		out = append(out, k)
		if sub, ok := v.(map[string]any); ok {
			for sk := range sub {
				out = append(out, k+"."+sk)
			}
		}
	}
	return out
}

func TestPreloginExistingUser(t *testing.T) {
	rec, raw, resp := post(t, New(&fakeUsers{u: alice}, []byte("secret")), `{"email":" Alice@Example.com "}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	if resp.KDF != (dto.KDF{Time: 2, MemoryKiB: 1024, Threads: 1}) || !bytes.Equal(resp.MasterSalt, alice.MasterSalt) || !bytes.Equal(resp.RecoverySalt, alice.RecoverySalt) {
		t.Fatalf("resp %+v", resp)
	}
	if _, ok := raw["master_salt"].(string); !ok {
		t.Fatalf("master_salt not base64 string: %v", raw)
	}
}

func TestPreloginUnknownEmail(t *testing.T) {
	users := &fakeUsers{u: alice}
	h := New(users, []byte("secret"))
	known, knownRaw, _ := post(t, h, `{"email":"alice@example.com"}`)
	rec, raw, resp := post(t, h, `{"email":"bob@example.com"}`)
	if rec.Code != known.Code || rec.Header().Get("Content-Type") != known.Header().Get("Content-Type") {
		t.Fatalf("status/content-type differ: %d %d", rec.Code, known.Code)
	}
	a, b := keysOf(raw), keysOf(knownRaw)
	if len(a) != len(b) {
		t.Fatalf("shape differs: %v vs %v", a, b)
	}
	d := keys.DefaultParams
	if resp.KDF != (dto.KDF{Time: d.Time, MemoryKiB: d.MemoryKiB, Threads: d.Threads}) {
		t.Fatalf("kdf %+v", resp.KDF)
	}
	if len(resp.MasterSalt) != 16 || len(resp.RecoverySalt) != 16 || bytes.Equal(resp.MasterSalt, resp.RecoverySalt) {
		t.Fatalf("salts %x %x", resp.MasterSalt, resp.RecoverySalt)
	}

	_, _, again := post(t, h, `{"email":"Bob@example.com"}`)
	if !reflect.DeepEqual(again, resp) {
		t.Fatal("not deterministic")
	}
	_, _, carol := post(t, h, `{"email":"carol@example.com"}`)
	if bytes.Equal(carol.MasterSalt, resp.MasterSalt) || bytes.Equal(carol.RecoverySalt, resp.RecoverySalt) {
		t.Fatal("salts equal across emails")
	}
	_, _, other := post(t, New(users, []byte("other")), `{"email":"bob@example.com"}`)
	if bytes.Equal(other.MasterSalt, resp.MasterSalt) || bytes.Equal(other.RecoverySalt, resp.RecoverySalt) {
		t.Fatal("salts equal across secrets")
	}
}

func TestPreloginErrors(t *testing.T) {
	h := New(&fakeUsers{}, []byte("secret"))
	for _, body := range []string{`{"email":"not-an-email"}`, `{}`, `nope`} {
		if rec, raw, _ := post(t, h, body); rec.Code != http.StatusBadRequest || raw["error"] != "invalid_request" {
			t.Errorf("%q: %d %v", body, rec.Code, raw)
		}
	}
	rec, raw, _ := post(t, New(&fakeUsers{err: errors.New("db")}, []byte("s")), `{"email":"a@b.com"}`)
	if rec.Code != http.StatusInternalServerError || raw["error"] != "internal" {
		t.Fatalf("%d %v", rec.Code, raw)
	}
}
