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

// NewDelete removes one item by name; without a name, the TUI lets the user pick it.
func NewDelete(find GetFunc, list ListFunc, del DeleteFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, arg string) error {
		var it dto.Item
		var skipped int
		var err error
		switch {
		case arg != "":
			it, skipped, err = find(ctx, s, arg)
		case p.Pick == nil:
			fmt.Fprintln(p.Out, "uso: delete <nome>")
			return nil
		default:
			var items []dto.Item
			if items, skipped, err = list(ctx, s); err == nil {
				if len(items) == 0 {
					fmt.Fprintln(p.Out, "cofre vazio")
					warnSkipped(p, skipped)
					return nil
				}
				i, ok := p.Pick(entries(items))
				if !ok {
					warnSkipped(p, skipped)
					return nil
				}
				it = items[i]
			}
		}
		if err == nil {
			err = confirmDelete(ctx, p, s, it, del)
		}
		if err != nil {
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
		}
		warnSkipped(p, skipped)
		return err
	}
}

func confirmDelete(ctx context.Context, p *cli.Prompter, s *cli.Session, it dto.Item, del DeleteFunc) error {
	done := p.OpenBox("remover item")
	answer, err := p.Line("remover " + it.Name + "? (s/N) ")
	if err == nil && strings.TrimSpace(answer) != "s" {
		done(false)
		fmt.Fprintln(p.Out, "remoção cancelada")
		return nil
	}
	if err == nil {
		err = del(ctx, s, it.ID)
	}
	if err != nil {
		done(false)
		return err
	}
	fmt.Fprintln(p.Out, "item removido")
	done(true)
	return nil
}
