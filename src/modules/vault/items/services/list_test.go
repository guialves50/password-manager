package services

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
)

func TestListSortsNamesIgnoringCase(t *testing.T) {
	s := session(t)
	tampered := row(t, s, "id-4", dto.Item{Name: "bad", Password: "p"})
	tampered.Blob[0] ^= 1
	repo := &fakeRepo{rows: []repository.Item{
		row(t, s, "id-1", dto.Item{Name: "github", Password: "p"}),
		row(t, s, "id-2", dto.Item{Name: "Zoom", Password: "p"}),
		row(t, s, "id-3", dto.Item{Name: "Amazon", Password: "p"}),
		tampered,
	}}

	names, skipped, err := (&ListService{Repo: repo}).List(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Amazon", "github", "Zoom"}; !slices.Equal(names, want) {
		t.Fatalf("names %q, want %q", names, want)
	}
	if skipped != 1 {
		t.Fatalf("skipped %d", skipped)
	}
	if len(repo.listedFor) != 1 || repo.listedFor[0] != 42 {
		t.Fatalf("listed for %v", repo.listedFor)
	}
}

func TestListEmpty(t *testing.T) {
	names, skipped, err := (&ListService{Repo: &fakeRepo{}}).List(context.Background(), session(t))
	if err != nil || len(names) != 0 || skipped != 0 {
		t.Fatalf("got %q, %d, %v", names, skipped, err)
	}
}

func TestListPropagatesRepoError(t *testing.T) {
	boom := errors.New("db down")
	if _, _, err := (&ListService{Repo: &fakeRepo{listErr: boom}}).List(context.Background(), session(t)); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
