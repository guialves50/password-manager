package controllers

import (
	"context"
	"fmt"
	"strings"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type DeleteFunc func(ctx context.Context, s *cli.Session, id string) error

func NewDelete(find GetFunc, del DeleteFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, arg string) error {
		if arg == "" {
			fmt.Fprintln(p.Out, "uso: delete <nome>")
			return nil
		}
		it, skipped, err := find(ctx, s, arg)
		if err == nil {
			err = confirmDelete(ctx, p, s, it, del)
		}
		if err != nil {
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
		}
		if skipped > 0 {
			fmt.Fprintf(p.Out, "aviso: %d item(ns) ignorado(s) por falha de integridade\n", skipped)
		}
		return err
	}
}

func confirmDelete(ctx context.Context, p *cli.Prompter, s *cli.Session, it dto.Item, del DeleteFunc) error {
	answer, err := p.Line("remover " + it.Name + "? (s/N) ")
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != "s" {
		fmt.Fprintln(p.Out, "remoção cancelada")
		return nil
	}
	if err := del(ctx, s, it.ID); err != nil {
		return err
	}
	fmt.Fprintln(p.Out, "item removido")
	return nil
}
