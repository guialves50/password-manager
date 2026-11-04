package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
)

type fakeSessions map[string]uint64

func (f fakeSessions) Touch(_ context.Context, token string, _ time.Time) (uint64, bool, error) {
	id, ok := f[token]
	return id, ok, nil
}

var sessions = fakeSessions{"alice": 1, "bob": 2}

func serve(h http.HandlerFunc, token string, req *http.Request) *httptest.ResponseRecorder {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	session.Require(sessions, time.Now)(h).ServeHTTP(rec, req)
	return rec
}

func errorCode(rec *httptest.ResponseRecorder) string {
	var e struct{ Error string }
	json.Unmarshal(rec.Body.Bytes(), &e)
	return e.Error
}

type fakeList struct {
	byUser map[uint64][]repository.Item
	asked  []uint64
	err    error
}

func (f *fakeList) ListByUser(_ context.Context, userID uint64) ([]repository.Item, error) {
	f.asked = append(f.asked, userID)
	return f.byUser[userID], f.err
}

func TestListReturnsOnlySessionUserItemsInOrder(t *testing.T) {
	repo := &fakeList{byUser: map[uint64][]repository.Item{
		1: {{ID: "b", UserID: 1, Blob: []byte("blob-b")}, {ID: "a", UserID: 1, Blob: []byte("blob-a")}},
		2: {{ID: "c", UserID: 2, Blob: []byte("blob-c")}},
	}}
	rec := serve(NewList(repo), "alice", httptest.NewRequest("GET", "/items?user_id=2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d %q", rec.Code, rec.Body)
	}
	var got []dto.StoredItem
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "b" || string(got[0].Blob) != "blob-b" || got[1].ID != "a" || string(got[1].Blob) != "blob-a" {
		t.Fatalf("items %+v", got)
	}
	if len(repo.asked) != 1 || repo.asked[0] != 1 {
		t.Fatalf("asked %v", repo.asked)
	}
}

func TestListEmptyIsArray(t *testing.T) {
	rec := serve(NewList(&fakeList{}), "bob", httptest.NewRequest("GET", "/items", nil))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestListWithoutSession(t *testing.T) {
	repo := &fakeList{}
	rec := serve(NewList(repo), "", httptest.NewRequest("GET", "/items", nil))
	if rec.Code != http.StatusUnauthorized || errorCode(rec) != "unauthorized" || len(repo.asked) != 0 {
		t.Fatalf("%d %q asked=%v", rec.Code, rec.Body, repo.asked)
	}
}

func TestListRepoError(t *testing.T) {
	rec := serve(NewList(&fakeList{err: errors.New("db")}), "alice", httptest.NewRequest("GET", "/items", nil))
	if rec.Code != http.StatusInternalServerError || errorCode(rec) != "internal" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}
