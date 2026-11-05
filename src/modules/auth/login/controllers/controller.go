package controllers

import (
	"context"
	"fmt"
	"strings"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
)

type LoginFunc func(ctx context.Context, in dto.Input) (*cli.Session, error)

type LogoutFunc func(ctx context.Context, token string) error

func New(login LoginFunc, logout LogoutFunc, cmds map[string]cli.SessionCommand) cli.Command {
	return func(ctx context.Context, p *cli.Prompter) error {
		s, usedCode, err := run(ctx, p, login)
		if err != nil {
			fmt.Fprintln(p.Out, autherrors.Message(err))
			return err
		}
		if usedCode && p.ShowCheck != nil {
			p.ShowCheck()
		}
		cli.Shell(ctx, p, s, cmds)
		logout(ctx, s.Token)
		return nil
	}
}

func run(ctx context.Context, p *cli.Prompter, login LoginFunc) (*cli.Session, bool, error) {
	email, err := p.Line("email: ")
	if err != nil {
		return nil, false, err
	}
	pw, err := p.Secret("senha mestra: ")
	if err != nil {
		keys.Zero(pw)
		return nil, false, err
	}
	usedCode := false
	code := func() (string, error) {
		usedCode = true
		c, err := p.Line("código 2FA: ")
		return strings.TrimSpace(c), err
	}
	s, err := login(ctx, dto.Input{Email: email, Password: pw, Code: code})
	return s, usedCode, err
}
