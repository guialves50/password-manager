package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type AddFunc func(ctx context.Context, s *cli.Session, in dto.Item) error

func NewAdd(add AddFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, _ string) error {
		in, err := readItem(p)
		if err == nil {
			err = add(ctx, s, in)
		}
		if err != nil {
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
			return err
		}
		fmt.Fprintln(p.Out, "item salvo")
		return nil
	}
}

func readItem(p *cli.Prompter) (dto.Item, error) {
	var in dto.Item
	var err error
	if in.Name, err = p.Line("nome: "); err != nil {
		return in, err
	}
	if in.Username, err = p.Line("usuário: "); err != nil {
		return in, err
	}
	pw, err := p.Secret("senha: ")
	in.Password = string(pw)
	keys.Zero(pw)
	if err != nil {
		return in, err
	}
	if in.URL, err = p.Line("url: "); err != nil {
		return in, err
	}
	in.Notes, err = p.Line("notas: ")
	return in, err
}
