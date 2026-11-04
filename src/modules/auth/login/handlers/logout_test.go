package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/modules/session"
)

type fakeTokens struct {
	live    map[string]uint64
	deleted []string
	err     error
}

func (f *fakeTokens) Touch(_ context.Context, token string, _ time.Time) (uint64, bool, error) {
	id, ok := f.live[token]
	return id, ok, nil
}

func (f *fakeTokens) Delete(_ context.Context, token string) error {
	f.deleted = append(f.deleted, token)
	if f.err != nil {
		return f.err
	}
	delete(f.live, token)
	return nil
}

func logout(store *fakeTokens, auth string) *httptest.ResponseRecorder {
	h := session.Require(store, func() time.Time { return clock })(NewLogout(store))
	req := httptest.NewRequest("POST", "/logout", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLogoutDeletesExactToken(t *testing.T) {
	store := &fakeTokens{live: map[string]uint64{"a": 1, "b": 1}}
	if rec := logout(store, "Bearer a"); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	if len(store.deleted) != 1 || store.deleted[0] != "a" {
		t.Fatalf("deleted %v", store.deleted)
	}
	if _, ok := store.live["b"]; !ok {
		t.Fatal("other session deleted")
	}
	if rec := logout(store, "Bearer a"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("reused token: %d", rec.Code)
	}
}

func TestLogoutWithoutToken(t *testing.T) {
	store := &fakeTokens{live: map[string]uint64{"a": 1}}
	for _, auth := range []string{"", "Bearer ", "Basic a"} {
		rec := logout(store, auth)
		if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"unauthorized"}` {
			t.Errorf("%q: %d %q", auth, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	NewLogout(store)(rec, httptest.NewRequest("POST", "/logout", nil))
	if rec.Code != http.StatusUnauthorized || len(store.deleted) != 0 {
		t.Fatalf("unwrapped: %d deleted=%v", rec.Code, store.deleted)
	}
}

func TestLogoutDeleteError(t *testing.T) {
	store := &fakeTokens{live: map[string]uint64{"a": 1}, err: errors.New("db")}
	if rec := logout(store, "Bearer a"); rec.Code != http.StatusInternalServerError || strings.TrimSpace(rec.Body.String()) != `{"error":"internal"}` {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}
