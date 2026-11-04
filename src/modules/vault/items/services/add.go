package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
)

type addRepo interface {
	lister
	Create(ctx context.Context, it *repository.Item) error
}

type AddService struct {
	Repo addRepo
}

func (a *AddService) Add(ctx context.Context, s *cli.Session, in dto.Item) error {
	in.Name = strings.TrimSpace(in.Name)
	n := utf8.RuneCountInString
	switch {
	case n(in.Name) < 1 || n(in.Name) > 100:
		return vaulterrors.ErrNameLength
	case n(in.Password) < 1 || n(in.Password) > 1024:
		return vaulterrors.ErrPasswordLength
	case n(in.Username) > 254:
		return vaulterrors.ErrUsernameLength
	case n(in.URL) > 2048:
		return vaulterrors.ErrURLLength
	case n(in.Notes) > 4096:
		return vaulterrors.ErrNotesLength
	}

	items, _, err := decryptAll(ctx, a.Repo, s)
	if err != nil {
		return err
	}
	for _, it := range items {
		if strings.EqualFold(it.Name, in.Name) {
			return vaulterrors.ErrNameTaken
		}
	}

	raw, err := keys.Random(16)
	if err != nil {
		return err
	}
	id := hex.EncodeToString(raw)
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	blob, err := keys.Seal(s.VaultKey, payload, aad(s.UserID, id))
	keys.Zero(payload)
	if err != nil {
		return err
	}
	return a.Repo.Create(ctx, &repository.Item{ID: id, UserID: s.UserID, Blob: blob})
}
