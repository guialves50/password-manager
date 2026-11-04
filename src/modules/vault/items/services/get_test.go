package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
)

func TestGetFindsOldestMatchIgnoringCase(t *testing.T) {
	s := session(t)
	older := dto.Item{Name: "gmail", Username: "alice", Password: "antiga", URL: "https://mail.google.com", Notes: "n"}
	bank := dto.Item{Name: "conta banco", Password: "1234"}
	repo := &fakeRepo{rows: []repository.Item{
		row(t, s, "id-1", older),
		row(t, s, "id-2", dto.Item{Name: "Gmail", Password: "nova"}),
		row(t, s, "id-3", bank),
	}}
	svc := &GetService{Repo: repo}
	older.ID, bank.ID = "id-1", "id-3"

	for _, name := range []string{"GMAIL", "  gmail  "} {
		got, skipped, err := svc.Get(context.Background(), s, name)
		if err != nil || got != older || skipped != 0 {
			t.Errorf("%q: got %+v, %d, %v", name, got, skipped, err)
		}
	}
	if got, _, err := svc.Get(context.Background(), s, "conta banco"); err != nil || got != bank {
		t.Errorf("conta banco: got %+v, %v", got, err)
	}
	if repo.listedFor[0] != 42 {
		t.Fatalf("listed for %v", repo.listedFor)
	}
}

func TestGetNotFound(t *testing.T) {
	s := session(t)
	repo := &fakeRepo{rows: []repository.Item{row(t, s, "id-1", dto.Item{Name: "gmail", Password: "p"})}}
	got, skipped, err := (&GetService{Repo: repo}).Get(context.Background(), s, "outlook")
	if !errors.Is(err, vaulterrors.ErrNotFound) || got != (dto.Item{}) || skipped != 0 {
		t.Fatalf("got %+v, %d, %v", got, skipped, err)
	}
}

func TestGetNeverReturnsItemThatFailsIntegrity(t *testing.T) {
	s := session(t)
	plain, _ := json.Marshal(dto.Item{Name: "bank", Password: "segredo"})
	tampered := row(t, s, "id-3", dto.Item{Name: "bank", Password: "segredo"})
	tampered.Blob[len(tampered.Blob)-1] ^= 1
	repo := &fakeRepo{rows: []repository.Item{
		sealRow(t, s.VaultKey, s.UserID, "id-1", "id-original", plain),
		sealRow(t, s.VaultKey, 7, "id-2", "id-2", plain),
		tampered,
	}}

	got, skipped, err := (&GetService{Repo: repo}).Get(context.Background(), s, "bank")
	if !errors.Is(err, vaulterrors.ErrNotFound) || got != (dto.Item{}) || skipped != 3 {
		t.Fatalf("got %+v, %d, %v", got, skipped, err)
	}
}

func TestGetPropagatesRepoError(t *testing.T) {
	boom := errors.New("db down")
	if _, _, err := (&GetService{Repo: &fakeRepo{listErr: boom}}).Get(context.Background(), session(t), "x"); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
