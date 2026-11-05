package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	token  string
	userID uint64
	err    error
	gotNow time.Time
	calls  int
}

func (f *fakeStore) Touch(_ context.Context, token string, now time.Time) (uint64, bool, error) {
	f.calls++
	f.gotNow = now
	if f.err != nil {
		return 0, false, f.err
	}
	if token != f.token {
		return 0, false, nil
	}
	return f.userID, true, nil
}

var clock = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func serve(store *fakeStore, auth string) (*httptest.ResponseRecorder, uint64, bool) {
	var got uint64
	reached := false
	h := Require(store, func() time.Time { return clock })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		got = UserID(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest("GET", "/items", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, got, reached
}

func TestRequireValid(t *testing.T) {
	store := &fakeStore{token: "tok", userID: 42}
	rec, id, reached := serve(store, "Bearer tok")
	if rec.Code != http.StatusNoContent || !reached || id != 42 {
		t.Fatalf("code=%d reached=%v id=%d", rec.Code, reached, id)
	}
	if !store.gotNow.Equal(clock) {
		t.Fatalf("touch called with %v", store.gotNow)
	}
}

func TestRequireRejects(t *testing.T) {
	for _, auth := range []string{"", "tok", "Bearer", "Bearer ", "Basic tok", "bearer tok", "Bearer other"} {
		rec, _, reached := serve(&fakeStore{token: "tok", userID: 42}, auth)
		if rec.Code != http.StatusUnauthorized || reached || strings.TrimSpace(rec.Body.String()) != `{"error":"unauthorized"}` {
			t.Errorf("%q: code=%d reached=%v body=%q", auth, rec.Code, reached, rec.Body)
		}
	}
}

func TestRequireStoreError(t *testing.T) {
	rec, _, reached := serve(&fakeStore{err: errors.New("db down")}, "Bearer tok")
	if rec.Code != http.StatusInternalServerError || reached || strings.TrimSpace(rec.Body.String()) != `{"error":"internal"}` {
		t.Fatalf("code=%d reached=%v body=%q", rec.Code, reached, rec.Body)
	}
}

func TestUserIDMissing(t *testing.T) {
	if UserID(context.Background()) != 0 {
		t.Fatal("expected 0 without session")
	}
}
