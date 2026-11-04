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
)

type addRepo interface {
	lister
	CreateItem(ctx context.Context, s *cli.Session, id string, blob []byte) error
}

type AddService struct {
	Repo addRepo
}

func (a *AddService) Add(ctx context.Context, s *cli.Session, in dto.Item) (int, error) {
	for _, f := range []string{in.Name, in.Username, in.Password, in.URL, in.Notes} {
		if !utf8.ValidString(f) {
			return 0, vaulterrors.ErrInvalidText
		}
	}
	in.Name = strings.TrimSpace(in.Name)
	n := utf8.RuneCountInString
	switch {
	case n(in.Name) < 1 || n(in.Name) > 100:
		return 0, vaulterrors.ErrNameLength
	case n(in.Password) < 1 || n(in.Password) > 1024:
		return 0, vaulterrors.ErrPasswordLength
	case n(in.Username) > 254:
		return 0, vaulterrors.ErrUsernameLength
	case n(in.URL) > 2048:
		return 0, vaulterrors.ErrURLLength
	case n(in.Notes) > 4096:
		return 0, vaulterrors.ErrNotesLength
	}

	items, skipped, err := decryptAll(ctx, a.Repo, s)
	if err != nil {
		return 0, err
	}
	for _, it := range items {
		if strings.EqualFold(it.Name, in.Name) {
			return skipped, vaulterrors.ErrNameTaken
		}
	}

	raw, err := keys.Random(16)
	if err != nil {
		return skipped, err
	}
	id := hex.EncodeToString(raw)
	payload, err := json.Marshal(in)
	if err != nil {
		return skipped, err
	}
	blob, err := keys.Seal(s.VaultKey, payload, aad(s.UserID, id))
	keys.Zero(payload)
	if err != nil {
		return skipped, err
	}
	return skipped, a.Repo.CreateItem(ctx, s, id, blob)
}
