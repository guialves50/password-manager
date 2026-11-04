package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeDelete struct {
	owner map[string]uint64
	calls []uint64
	err   error
}

func (f *fakeDelete) Delete(_ context.Context, userID uint64, id string) (bool, error) {
	f.calls = append(f.calls, userID)
	if f.err != nil {
		return false, f.err
	}
	if owner, ok := f.owner[id]; ok && owner == userID {
		delete(f.owner, id)
		return true, nil
	}
	return false, nil
}

func deleteItem(repo *fakeDelete, token, id string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.Handle("DELETE /items/{id}", NewDelete(repo))
	return serve(mux.ServeHTTP, token, httptest.NewRequest("DELETE", "/items/"+id+"?user_id=1", nil))
}

func TestDeleteOwnItem(t *testing.T) {
	repo := &fakeDelete{owner: map[string]uint64{hexID: 1}}
	if rec := deleteItem(repo, "alice", hexID); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	if _, ok := repo.owner[hexID]; ok {
		t.Fatal("item not deleted")
	}
}

func TestDeleteOtherUsersItemIsNotFound(t *testing.T) {
	repo := &fakeDelete{owner: map[string]uint64{hexID: 1}}
	rec := deleteItem(repo, "bob", hexID)
	if rec.Code != http.StatusNotFound || errorCode(rec) != "not_found" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	if repo.owner[hexID] != 1 || len(repo.calls) != 1 || repo.calls[0] != 2 {
		t.Fatalf("owner=%v calls=%v", repo.owner, repo.calls)
	}
}

func TestDeleteMissingItemIsNotFound(t *testing.T) {
	rec := deleteItem(&fakeDelete{}, "alice", hexID)
	if rec.Code != http.StatusNotFound || errorCode(rec) != "not_found" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestDeleteWithoutSession(t *testing.T) {
	repo := &fakeDelete{owner: map[string]uint64{hexID: 1}}
	rec := deleteItem(repo, "", hexID)
	if rec.Code != http.StatusUnauthorized || errorCode(rec) != "unauthorized" || len(repo.calls) != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

func TestDeleteRepoError(t *testing.T) {
	rec := deleteItem(&fakeDelete{err: errors.New("db")}, "alice", hexID)
	if rec.Code != http.StatusInternalServerError || errorCode(rec) != "internal" {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}
