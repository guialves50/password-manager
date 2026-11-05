package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type GetFunc func(ctx context.Context, s *cli.Session, name string) (dto.Item, int, error)

// NewGet shows one item by name; without a name, the TUI lets the user browse.
func NewGet(get GetFunc, list ListFunc) cli.SessionCommand {
	browse := NewList(list)
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, arg string) error {
		if arg == "" {
			if p.Browse == nil {
				fmt.Fprintln(p.Out, "uso: get <nome>")
				return nil
			}
			return browse(ctx, p, s, "")
		}
		it, skipped, err := get(ctx, s, arg)
		switch {
		case err != nil:
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
		case p.Show != nil:
			p.Show(entries([]dto.Item{it})[0])
		default:
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
		warnSkipped(p, skipped)
		return err
	}
}

func warnSkipped(p *cli.Prompter, skipped int) {
	if skipped > 0 {
		fmt.Fprintf(p.Out, "aviso: %d item(ns) ignorado(s) por falha de integridade\n", skipped)
	}
}
