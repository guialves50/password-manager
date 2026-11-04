package services

import (
	"context"
	"strings"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type GetService struct {
	Repo lister
}

func (g *GetService) Get(ctx context.Context, s *cli.Session, name string) (dto.Item, int, error) {
	items, skipped, err := decryptAll(ctx, g.Repo, s)
	if err != nil {
		return dto.Item{}, 0, err
	}
	name = strings.TrimSpace(name)
	for _, it := range items {
		if strings.EqualFold(it.Name, name) {
			return it, skipped, nil
		}
	}
	return dto.Item{}, skipped, vaulterrors.ErrNotFound
}
