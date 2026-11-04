package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
)

type RegisterFunc func(ctx context.Context, in dto.Input) (dto.Output, error)

func New(register RegisterFunc) cli.Command {
	return func(ctx context.Context, p *cli.Prompter) error {
		out, err := run(ctx, p, register)
		if err != nil {
			fmt.Fprintln(p.Out, autherrors.Message(err))
			return err
		}
		fmt.Fprintln(p.Out, "conta criada")
		fmt.Fprintln(p.Out, "chave de recuperação:", out.RecoveryKey)
		fmt.Fprintln(p.Out, "guarde esta chave em local seguro: ela não pode ser exibida novamente")
		return nil
	}
}

func run(ctx context.Context, p *cli.Prompter, register RegisterFunc) (dto.Output, error) {
	email, err := p.Line("email: ")
	if err != nil {
		return dto.Output{}, err
	}
	pw, err := p.Secret("senha mestra: ")
	if err != nil {
		keys.Zero(pw)
		return dto.Output{}, err
	}
	confirm, err := p.Secret("confirme a senha mestra: ")
	if err != nil {
		keys.Zero(pw)
		keys.Zero(confirm)
		return dto.Output{}, err
	}
	return register(ctx, dto.Input{Email: email, Password: pw, Confirm: confirm})
}
