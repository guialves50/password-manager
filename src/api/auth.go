package api

import (
	"context"
	"errors"

	login "github.com/guialves50/password-manager/src/modules/auth/login/dto"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	recovery "github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	register "github.com/guialves50/password-manager/src/modules/auth/register/dto"
)

func (c *Client) Prelogin(ctx context.Context, email string) (prelogin.Response, error) {
	var out prelogin.Response
	if err := c.do(ctx, "POST", "/prelogin", "", prelogin.Request{Email: email}, &out); err != nil {
		return prelogin.Response{}, err
	}
	if out.KDF.Time == 0 || out.KDF.MemoryKiB == 0 || out.KDF.Threads == 0 || len(out.MasterSalt) != 16 || len(out.RecoverySalt) != 16 {
		return prelogin.Response{}, errors.New("api: invalid prelogin response")
	}
	return out, nil
}

func (c *Client) Register(ctx context.Context, req register.Request) error {
	return c.do(ctx, "POST", "/register", "", req, nil)
}

func (c *Client) Login(ctx context.Context, req login.Request) (login.Response, error) {
	var out login.Response
	err := c.do(ctx, "POST", "/login", "", req, &out)
	return out, err
}

func (c *Client) Logout(ctx context.Context, token string) error {
	return c.do(ctx, "POST", "/logout", token, nil, nil)
}

func (c *Client) RecoverStart(ctx context.Context, req recovery.StartRequest) (recovery.StartResponse, error) {
	var out recovery.StartResponse
	err := c.do(ctx, "POST", "/recover/start", "", req, &out)
	return out, err
}

func (c *Client) RecoverFinish(ctx context.Context, req recovery.FinishRequest) error {
	return c.do(ctx, "POST", "/recover/finish", "", req, nil)
}
