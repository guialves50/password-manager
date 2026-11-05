package services

import (
	"context"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
)

type deleter interface {
	DeleteItem(ctx context.Context, s *cli.Session, id string) (bool, error)
}

type DeleteService struct {
	Repo deleter
}

func (d *DeleteService) Delete(ctx context.Context, s *cli.Session, id string) error {
	ok, err := d.Repo.DeleteItem(ctx, s, id)
	if err != nil {
		return err
	}
	if !ok {
		return vaulterrors.ErrNotFound
	}
	return nil
}
