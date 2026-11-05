package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

func TestListSortsNamesIgnoringCase(t *testing.T) {
	s := session(t)
	tampered := row(t, s, "id-4", dto.Item{Name: "bad", Password: "p"})
	tampered.Blob[0] ^= 1
	repo := &fakeRepo{rows: []dto.StoredItem{
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

func TestListOrdersByLowercaseBytes(t *testing.T) {
	s := session(t)
	var rows []dto.StoredItem
	for i, name := range []string{"zoom", "Ábaco", "ab", "a_b", "Amazon"} {
		rows = append(rows, row(t, s, fmt.Sprintf("id-%d", i), dto.Item{Name: name, Password: "p"}))
	}

	names, _, err := (&ListService{Repo: &fakeRepo{rows: rows}}).List(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a_b", "ab", "Amazon", "zoom", "Ábaco"}; !slices.Equal(names, want) {
		t.Fatalf("names %q, want %q", names, want)
	}
}

func TestItemsSortedWithAllFields(t *testing.T) {
	s := session(t)
	repo := &fakeRepo{rows: []dto.StoredItem{
		row(t, s, "id-1", dto.Item{Name: "github", Username: "ana", Password: "p1", URL: "https://github.com", Notes: "n"}),
		row(t, s, "id-2", dto.Item{Name: "Amazon", Password: "p2"}),
	}}
	items, skipped, err := (&ListService{Repo: repo}).Items(context.Background(), s)
	if err != nil || skipped != 0 || len(items) != 2 {
		t.Fatalf("%+v %d %v", items, skipped, err)
	}
	if items[0].Name != "Amazon" || items[0].Password != "p2" {
		t.Fatalf("first %+v", items[0])
	}
	if it := items[1]; it.Name != "github" || it.Username != "ana" || it.Password != "p1" || it.URL != "https://github.com" || it.Notes != "n" {
		t.Fatalf("second %+v", it)
	}
}
