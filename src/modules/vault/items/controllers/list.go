package controllers

import (
	"context"
	"fmt"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type ListFunc func(ctx context.Context, s *cli.Session) ([]dto.Item, int, error)

func NewList(list ListFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, _ string) error {
		items, skipped, err := list(ctx, s)
		if err != nil {
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
			return err
		}
		switch {
		case len(items) == 0:
			fmt.Fprintln(p.Out, "cofre vazio")
		case p.Browse != nil:
			p.Browse(entries(items))
		default:
			for _, it := range items {
				fmt.Fprintln(p.Out, it.Name)
			}
		}
		if skipped > 0 {
			fmt.Fprintf(p.Out, "aviso: %d item(ns) ignorado(s) por falha de integridade\n", skipped)
		}
		return nil
	}
}

// entries carries the same fields get prints; empty optional fields are left out.
func entries(items []dto.Item) []cli.Entry {
	out := make([]cli.Entry, len(items))
	for i, it := range items {
		fields := []cli.Field{}
		if it.Username != "" {
			fields = append(fields, cli.Field{Label: "usuário", Value: it.Username})
		}
		fields = append(fields, cli.Field{Label: "senha", Value: it.Password, Secret: true})
		if it.URL != "" {
			fields = append(fields, cli.Field{Label: "url", Value: it.URL})
		}
		if it.Notes != "" {
			fields = append(fields, cli.Field{Label: "notas", Value: it.Notes})
		}
		out[i] = cli.Entry{Title: it.Name, Fields: fields}
	}
	return out
}
