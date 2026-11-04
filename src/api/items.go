package api

import (
	"context"
	"errors"
	"net/url"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

func (c *Client) ListItems(ctx context.Context, s *cli.Session) ([]dto.StoredItem, error) {
	var out []dto.StoredItem
	err := c.do(ctx, "GET", "/items", s.Token, nil, &out)
	return out, err
}

func (c *Client) CreateItem(ctx context.Context, s *cli.Session, id string, blob []byte) error {
	return c.do(ctx, "POST", "/items", s.Token, dto.StoredItem{ID: id, Blob: blob}, nil)
}

func (c *Client) DeleteItem(ctx context.Context, s *cli.Session, id string) (bool, error) {
	err := c.do(ctx, "DELETE", "/items/"+url.PathEscape(id), s.Token, nil, nil)
	if errors.Is(err, vaulterrors.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
