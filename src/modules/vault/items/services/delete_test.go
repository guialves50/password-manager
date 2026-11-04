package services

import (
	"context"
	"errors"
	"testing"

	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
)

type fakeDeleter struct {
	ok      bool
	err     error
	userIDs []uint64
	ids     []string
}

func (f *fakeDeleter) Delete(_ context.Context, userID uint64, id string) (bool, error) {
	f.userIDs = append(f.userIDs, userID)
	f.ids = append(f.ids, id)
	return f.ok, f.err
}

func TestDeleteUsesSessionUser(t *testing.T) {
	boom := errors.New("db down")
	cases := []struct {
		name string
		repo *fakeDeleter
		want error
	}{
		{"deleted", &fakeDeleter{ok: true}, nil},
		{"nothing deleted", &fakeDeleter{}, vaulterrors.ErrNotFound},
		{"repo error", &fakeDeleter{err: boom}, boom},
	}
	for _, c := range cases {
		err := (&DeleteService{Repo: c.repo}).Delete(context.Background(), session(t), "abc123")
		if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		if len(c.repo.userIDs) != 1 || c.repo.userIDs[0] != 42 || c.repo.ids[0] != "abc123" {
			t.Errorf("%s: repo got %v %v", c.name, c.repo.userIDs, c.repo.ids)
		}
	}
}
