package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
)

type LoginFunc func(ctx context.Context, in dto.Input) (*cli.Session, error)

func New(login LoginFunc) cli.Command {
	return func(ctx context.Context, p *cli.Prompter) error {
		s, err := run(ctx, p, login)
		if err != nil {
			fmt.Fprintln(p.Out, autherrors.Message(err))
			return err
		}
		cli.Shell(p.In, p.Out, s)
		return nil
	}
}

func run(ctx context.Context, p *cli.Prompter, login LoginFunc) (*cli.Session, error) {
	email, err := p.Line("email: ")
	if err != nil {
		return nil, err
	}
	pw, err := p.Secret("senha mestra: ")
	if err != nil {
		keys.Zero(pw)
		return nil, err
	}
	return login(ctx, dto.Input{Email: email, Password: pw})
}
