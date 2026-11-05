package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
)

type fakeCreate struct {
	got []repository.Item
	err error
}

func (f *fakeCreate) Create(_ context.Context, it *repository.Item) error {
	f.got = append(f.got, *it)
	return f.err
}

func postItem(repo *fakeCreate, token, body string) *httptest.ResponseRecorder {
	return serve(NewCreate(repo), token, httptest.NewRequest("POST", "/items", strings.NewReader(body)))
}

var hexID = strings.Repeat("0a", 16)

func TestCreateStoresForSessionUserIgnoringBodyUserID(t *testing.T) {
	repo := &fakeCreate{}
	rec := postItem(repo, "alice", `{"id":"`+hexID+`","blob":"AQID","user_id":2}`)
	if rec.Code != http.StatusCreated || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	if len(repo.got) != 1 || repo.got[0].ID != hexID || repo.got[0].UserID != 1 || !bytes.Equal(repo.got[0].Blob, []byte{1, 2, 3}) {
		t.Fatalf("stored %+v", repo.got)
	}
}

func TestCreateInvalidInput(t *testing.T) {
	bigBlob := `"` + strings.Repeat("A", 47<<10/3*4) + `"`
	for name, body := range map[string]string{
		"short id":     `{"id":"` + hexID[:31] + `","blob":"AQ=="}`,
		"long id":      `{"id":"` + hexID + `0","blob":"AQ=="}`,
		"uppercase id": `{"id":"` + strings.ToUpper(hexID) + `","blob":"AQ=="}`,
		"non hex id":   `{"id":"` + strings.Repeat("g", 32) + `","blob":"AQ=="}`,
		"missing id":   `{"blob":"AQ=="}`,
		"empty blob":   `{"id":"` + hexID + `","blob":""}`,
		"missing blob": `{"id":"` + hexID + `"}`,
		"not json":     `nope`,
	} {
		repo := &fakeCreate{}
		rec := postItem(repo, "alice", body)
		if rec.Code != http.StatusBadRequest || errorCode(rec) != "invalid_request" || len(repo.got) != 0 {
			t.Errorf("%s: %d %q stored=%d", name, rec.Code, rec.Body, len(repo.got))
		}
	}
	repo := &fakeCreate{}
	if rec := postItem(repo, "alice", `{"id":"`+hexID+`","blob":`+bigBlob+`}`); rec.Code != http.StatusCreated || len(repo.got) != 1 || len(repo.got[0].Blob) != 47<<10/3*3 {
		t.Fatalf("47 KiB blob: %d", rec.Code)
	}
	tooBig := `"` + strings.Repeat("A", (MaxBlob+3)/3*4) + `"`
	repo = &fakeCreate{}
	if rec := postItem(repo, "alice", `{"id":"`+hexID+`","blob":`+tooBig+`}`); rec.Code != http.StatusRequestEntityTooLarge || len(repo.got) != 0 {
		t.Fatalf("blob over 48 KiB: %d stored=%d", rec.Code, len(repo.got))
	}
}

func TestCreateWithoutSession(t *testing.T) {
	repo := &fakeCreate{}
	rec := postItem(repo, "", `{"id":"`+hexID+`","blob":"AQ=="}`)
	if rec.Code != http.StatusUnauthorized || errorCode(rec) != "unauthorized" || len(repo.got) != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestCreateRepoError(t *testing.T) {
	rec := postItem(&fakeCreate{err: errors.New("db")}, "alice", `{"id":"`+hexID+`","blob":"AQ=="}`)
	if rec.Code != http.StatusInternalServerError || errorCode(rec) != "internal" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}
