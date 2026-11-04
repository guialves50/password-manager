package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
)

type ListFunc func(ctx context.Context, s *cli.Session) ([]string, int, error)

func NewList(list ListFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, _ string) error {
		names, skipped, err := list(ctx, s)
		if err != nil {
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
			return err
		}
		if len(names) == 0 {
			fmt.Fprintln(p.Out, "cofre vazio")
		}
		for _, n := range names {
			fmt.Fprintln(p.Out, n)
		}
		if skipped > 0 {
			fmt.Fprintf(p.Out, "aviso: %d item(ns) ignorado(s) por falha de integridade\n", skipped)
		}
		return nil
	}
}
