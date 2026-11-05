package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
)

type RecoverFunc func(ctx context.Context, in dto.Input) (dto.Output, error)

func New(recover RecoverFunc) cli.Command {
	return func(ctx context.Context, p *cli.Prompter) error {
		done := p.OpenBox("recuperar conta")
		out, err := run(ctx, p, recover)
		if err != nil {
			done(false)
			fmt.Fprintln(p.Out, autherrors.Message(err))
			return err
		}
		fmt.Fprintln(p.Out, "senha mestra redefinida")
		fmt.Fprintln(p.Out, "chave de recuperação:", out.RecoveryKey)
		fmt.Fprintln(p.Out, "guarde esta chave em local seguro: ela não pode ser exibida novamente")
		cli.HoldKey(p)
		done(true)
		return nil
	}
}

func run(ctx context.Context, p *cli.Prompter, recover RecoverFunc) (dto.Output, error) {
	email, err := p.Line("email: ")
	if err != nil {
		return dto.Output{}, err
	}
	key, err := p.Secret("chave de recuperação: ")
	if err != nil {
		keys.Zero(key)
		return dto.Output{}, err
	}
	pw, err := p.Secret("nova senha mestra: ")
	if err != nil {
		keys.Zero(key)
		keys.Zero(pw)
		return dto.Output{}, err
	}
	confirm, err := p.Secret("confirme a nova senha mestra: ")
	if err != nil {
		keys.Zero(key)
		keys.Zero(pw)
		keys.Zero(confirm)
		return dto.Output{}, err
	}
	return recover(ctx, dto.Input{Email: email, RecoveryKey: key, Password: pw, Confirm: confirm})
}
