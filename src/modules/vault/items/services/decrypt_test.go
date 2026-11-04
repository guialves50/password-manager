package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
)

type fakeRepo struct {
	rows      []repository.Item
	listErr   error
	listedFor []uint64
	createErr error
	created   []repository.Item
}

func (f *fakeRepo) ListByUser(_ context.Context, userID uint64) ([]repository.Item, error) {
	f.listedFor = append(f.listedFor, userID)
	return f.rows, f.listErr
}

func (f *fakeRepo) Create(_ context.Context, it *repository.Item) error {
	f.created = append(f.created, *it)
	if f.createErr != nil {
		return f.createErr
	}
	f.rows = append(f.rows, *it)
	return nil
}

func session(t *testing.T) *cli.Session {
	t.Helper()
	vk, err := keys.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	return &cli.Session{UserID: 42, Email: "alice@example.com", VaultKey: vk}
}

func itemAAD(userID uint64, id string) []byte {
	return []byte(fmt.Sprintf("pm/item/v1|%d|%s", userID, id))
}

func sealRow(t *testing.T, key []byte, userID uint64, rowID, aadID string, plain []byte) repository.Item {
	t.Helper()
	blob, err := keys.Seal(key, plain, itemAAD(userID, aadID))
	if err != nil {
		t.Fatal(err)
	}
	return repository.Item{ID: rowID, UserID: 42, Blob: blob}
}

func row(t *testing.T, s *cli.Session, id string, it dto.Item) repository.Item {
	t.Helper()
	plain, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}
	return sealRow(t, s.VaultKey, s.UserID, id, id, plain)
}

func TestAAD(t *testing.T) {
	if got := string(aad(42, "0123abcd")); got != "pm/item/v1|42|0123abcd" {
		t.Fatalf("aad %q", got)
	}
}

func TestDecryptAllSkipsItemsThatFailIntegrity(t *testing.T) {
	s := session(t)
	otherKey, _ := keys.Random(32)
	gmail := dto.Item{Name: "gmail", Username: "alice", Password: "s3nha", URL: "https://mail.google.com", Notes: "pessoal"}
	bank := dto.Item{Name: "conta banco", Password: "1234"}
	plain, _ := json.Marshal(dto.Item{Name: "x", Password: "y"})
	tampered := row(t, s, "id-tampered", dto.Item{Name: "tampered", Password: "p"})
	tampered.Blob[len(tampered.Blob)-1] ^= 1

	repo := &fakeRepo{rows: []repository.Item{
		row(t, s, "id-1", gmail),
		sealRow(t, s.VaultKey, s.UserID, "id-swapped", "id-1", plain),
		sealRow(t, s.VaultKey, 7, "id-other-user", "id-other-user", plain),
		sealRow(t, otherKey, s.UserID, "id-other-key", "id-other-key", plain),
		tampered,
		sealRow(t, s.VaultKey, s.UserID, "id-not-json", "id-not-json", []byte("not json")),
		row(t, s, "id-2", bank),
	}}

	items, skipped, err := decryptAll(context.Background(), repo, s)
	if err != nil {
		t.Fatal(err)
	}
	gmail.ID, bank.ID = "id-1", "id-2"
	if len(items) != 2 || items[0] != gmail || items[1] != bank {
		t.Fatalf("items %+v", items)
	}
	if skipped != 5 {
		t.Fatalf("skipped %d", skipped)
	}
	if len(repo.listedFor) != 1 || repo.listedFor[0] != 42 {
		t.Fatalf("listed for %v", repo.listedFor)
	}
}

func TestDecryptAllPropagatesRepoError(t *testing.T) {
	boom := errors.New("db down")
	if _, _, err := decryptAll(context.Background(), &fakeRepo{listErr: boom}, session(t)); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
