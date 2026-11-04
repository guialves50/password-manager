package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
)

func valid() dto.Item {
	return dto.Item{Name: "gmail", Username: "alice@gmail.com", Password: "S3nhaDoGmail", URL: "https://mail.google.com", Notes: "conta pessoal"}
}

func TestAddSealsItemWithVaultKey(t *testing.T) {
	s := session(t)
	repo := &fakeRepo{}
	in := valid()
	in.Name = "  gmail  "

	if _, err := (&AddService{Repo: repo}).Add(context.Background(), s, in); err != nil {
		t.Fatal(err)
	}
	if len(repo.created) != 1 {
		t.Fatalf("created %d", len(repo.created))
	}
	got := repo.created[0]
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(got.ID) || got.UserID != 42 {
		t.Fatalf("row id %q user %d", got.ID, got.UserID)
	}
	plain, err := keys.Open(s.VaultKey, got.Blob, []byte("pm/item/v1|42|"+got.ID))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var item dto.Item
	if err := json.Unmarshal(plain, &item); err != nil {
		t.Fatal(err)
	}
	want := valid()
	if item != want {
		t.Fatalf("payload %+v, want %+v", item, want)
	}
	for _, field := range []string{want.Name, want.Username, want.Password, want.URL, want.Notes} {
		if bytes.Contains(got.Blob, []byte(field)) {
			t.Fatalf("field %q stored in clear", field)
		}
	}
	if _, err := keys.Open(s.VaultKey, got.Blob, []byte("pm/item/v1|7|"+got.ID)); err == nil {
		t.Fatal("blob opened with another user in AAD")
	}
}

func TestAddGeneratesRandomIDs(t *testing.T) {
	s := session(t)
	repo := &fakeRepo{}
	svc := &AddService{Repo: repo}
	for _, name := range []string{"a", "b"} {
		in := valid()
		in.Name = name
		if _, err := svc.Add(context.Background(), s, in); err != nil {
			t.Fatal(err)
		}
	}
	if len(repo.created) != 2 || repo.created[0].ID == repo.created[1].ID {
		t.Fatalf("ids %+v", repo.created)
	}
}

func TestAddLimitsInRunes(t *testing.T) {
	r := func(n int) string { return strings.Repeat("ã", n) }
	with := func(f func(*dto.Item)) dto.Item {
		in := valid()
		f(&in)
		return in
	}
	cases := []struct {
		name string
		in   dto.Item
		want error
	}{
		{"name 100", with(func(i *dto.Item) { i.Name = r(100) }), nil},
		{"name 100 after trim", with(func(i *dto.Item) { i.Name = "  " + r(100) + "  " }), nil},
		{"name 101", with(func(i *dto.Item) { i.Name = r(101) }), vaulterrors.ErrNameLength},
		{"name empty", with(func(i *dto.Item) { i.Name = "" }), vaulterrors.ErrNameLength},
		{"name blank", with(func(i *dto.Item) { i.Name = "   " }), vaulterrors.ErrNameLength},
		{"password 1024", with(func(i *dto.Item) { i.Password = r(1024) }), nil},
		{"password 1025", with(func(i *dto.Item) { i.Password = r(1025) }), vaulterrors.ErrPasswordLength},
		{"password empty", with(func(i *dto.Item) { i.Password = "" }), vaulterrors.ErrPasswordLength},
		{"username 254", with(func(i *dto.Item) { i.Username = r(254) }), nil},
		{"username 255", with(func(i *dto.Item) { i.Username = r(255) }), vaulterrors.ErrUsernameLength},
		{"url 2048", with(func(i *dto.Item) { i.URL = r(2048) }), nil},
		{"url 2049", with(func(i *dto.Item) { i.URL = r(2049) }), vaulterrors.ErrURLLength},
		{"notes 4096", with(func(i *dto.Item) { i.Notes = r(4096) }), nil},
		{"notes 4097", with(func(i *dto.Item) { i.Notes = r(4097) }), vaulterrors.ErrNotesLength},
		{"optional empty", dto.Item{Name: "x", Password: "y"}, nil},
	}
	for _, c := range cases {
		repo := &fakeRepo{}
		_, err := (&AddService{Repo: repo}).Add(context.Background(), session(t), c.in)
		if err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		wantCreated := 0
		if c.want == nil {
			wantCreated = 1
		}
		if len(repo.created) != wantCreated {
			t.Errorf("%s: created %d", c.name, len(repo.created))
		}
	}
}

func TestAddRejectsDuplicateNameIgnoringCase(t *testing.T) {
	s := session(t)
	repo := &fakeRepo{}
	svc := &AddService{Repo: repo}
	in := valid()
	in.Name = "Gmail"
	if _, err := svc.Add(context.Background(), s, in); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gmail", " GMAIL "} {
		in.Name = name
		if _, err := svc.Add(context.Background(), s, in); err != vaulterrors.ErrNameTaken {
			t.Errorf("%q: got %v", name, err)
		}
	}
	if len(repo.created) != 1 {
		t.Fatalf("created %d", len(repo.created))
	}
	if len(repo.listedFor) != 3 || repo.listedFor[2] != 42 {
		t.Fatalf("listed for %v", repo.listedFor)
	}
}

func TestAddRepoErrors(t *testing.T) {
	boom := errors.New("db down")
	repo := &fakeRepo{listErr: boom}
	if _, err := (&AddService{Repo: repo}).Add(context.Background(), session(t), valid()); !errors.Is(err, boom) || len(repo.created) != 0 {
		t.Fatalf("list error: %v created %d", err, len(repo.created))
	}
	repo = &fakeRepo{createErr: boom}
	if _, err := (&AddService{Repo: repo}).Add(context.Background(), session(t), valid()); !errors.Is(err, boom) {
		t.Fatalf("create error: %v", err)
	}
}

func TestAddIDIsIndependentOfName(t *testing.T) {
	s := session(t)
	var ids []string
	for range 2 {
		repo := &fakeRepo{}
		if _, err := (&AddService{Repo: repo}).Add(context.Background(), s, valid()); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, repo.created[0].ID)
	}
	if ids[0] == ids[1] {
		t.Fatalf("same name produced the same id %q", ids[0])
	}
	for _, id := range ids {
		if strings.Contains(id, hex.EncodeToString([]byte(valid().Name))) {
			t.Fatalf("id %q leaks the item name", id)
		}
	}
	a, _ := hex.DecodeString(ids[0])
	b, _ := hex.DecodeString(ids[1])
	same := 0
	for i := range a {
		if a[i] == b[i] {
			same++
		}
	}
	if same >= 4 {
		t.Fatalf("ids %q and %q share %d of 16 bytes for the same name", ids[0], ids[1], same)
	}
}

func TestAddTreatsInnerSpacesAsDistinctNames(t *testing.T) {
	s := session(t)
	repo := &fakeRepo{}
	svc := &AddService{Repo: repo}
	for _, name := range []string{"conta banco", "conta  banco"} {
		in := valid()
		in.Name = name
		if _, err := svc.Add(context.Background(), s, in); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
	}
	if len(repo.created) != 2 {
		t.Fatalf("created %d", len(repo.created))
	}
}

func TestAddReportsSkippedItems(t *testing.T) {
	s := session(t)
	tampered := row(t, s, "id-1", dto.Item{Name: "bad", Password: "p"})
	tampered.Blob[0] ^= 1
	repo := &fakeRepo{rows: []repository.Item{tampered}}

	skipped, err := (&AddService{Repo: repo}).Add(context.Background(), s, valid())
	if err != nil || skipped != 1 || len(repo.created) != 1 {
		t.Fatalf("skipped %d err %v created %d", skipped, err, len(repo.created))
	}

	in := valid()
	repo.rows = append(repo.rows, repo.created[0])
	if skipped, err := (&AddService{Repo: repo}).Add(context.Background(), s, in); err != vaulterrors.ErrNameTaken || skipped != 1 {
		t.Fatalf("duplicate: skipped %d err %v", skipped, err)
	}
}

func TestAddRejectsInvalidUTF8(t *testing.T) {
	bad := "S3nha\xff"
	for name, f := range map[string]func(*dto.Item){
		"name":     func(in *dto.Item) { in.Name = bad },
		"username": func(in *dto.Item) { in.Username = bad },
		"password": func(in *dto.Item) { in.Password = bad },
		"url":      func(in *dto.Item) { in.URL = bad },
		"notes":    func(in *dto.Item) { in.Notes = bad },
	} {
		in := valid()
		f(&in)
		repo := &fakeRepo{}
		if _, err := (&AddService{Repo: repo}).Add(context.Background(), session(t), in); err != vaulterrors.ErrInvalidText || len(repo.created) != 0 {
			t.Errorf("%s: err %v created %d", name, err, len(repo.created))
		}
	}
}
