package api

import (
	"context"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/twofactor/dto"
)

func (c *Client) Setup2FA(ctx context.Context, s *cli.Session) (dto.SetupResponse, error) {
	var out dto.SetupResponse
	err := c.do(ctx, "POST", "/2fa/setup", s.Token, nil, &out)
	return out, err
}

func (c *Client) Confirm2FA(ctx context.Context, s *cli.Session, code string) error {
	return c.do(ctx, "POST", "/2fa/confirm", s.Token, dto.ConfirmRequest{Code: code}, nil)
}
