package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type GetFunc func(ctx context.Context, s *cli.Session, name string) (dto.Item, int, error)

func NewGet(get GetFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, arg string) error {
		if arg == "" {
			fmt.Fprintln(p.Out, "uso: get <nome>")
			return nil
		}
		it, skipped, err := get(ctx, s, arg)
		if err != nil {
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
		} else {
			fmt.Fprintln(p.Out, "nome:", it.Name)
			if it.Username != "" {
				fmt.Fprintln(p.Out, "usuário:", it.Username)
			}
			fmt.Fprintln(p.Out, "senha:", it.Password)
			if it.URL != "" {
				fmt.Fprintln(p.Out, "url:", it.URL)
			}
			if it.Notes != "" {
				fmt.Fprintln(p.Out, "notas:", it.Notes)
			}
		}
		if skipped > 0 {
			fmt.Fprintf(p.Out, "aviso: %d item(ns) ignorado(s) por falha de integridade\n", skipped)
		}
		return err
	}
}
