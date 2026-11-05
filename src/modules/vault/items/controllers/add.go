package controllers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/guialves50/password-manager/src/cli"
	vaulterrors "github.com/guialves50/password-manager/src/modules/vault/errors"
	"github.com/guialves50/password-manager/src/modules/vault/generator"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
)

type AddFunc func(ctx context.Context, s *cli.Session, in dto.Item) (int, error)

type GenerateFunc func(n int) (string, error)

func NewAdd(add AddFunc, gen GenerateFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, _ string) error {
		in, err := readItem(p, gen)
		skipped := 0
		if err == nil {
			skipped, err = add(ctx, s, in)
		}
		if err != nil {
			fmt.Fprintln(p.Out, vaulterrors.Message(err))
		} else {
			fmt.Fprintln(p.Out, "item salvo")
		}
		if skipped > 0 {
			fmt.Fprintf(p.Out, "aviso: %d item(ns) ignorado(s) por falha de integridade\n", skipped)
		}
		return err
	}
}

func readItem(p *cli.Prompter, gen GenerateFunc) (dto.Item, error) {
	var in dto.Item
	var err error
	if in.Name, err = p.Line("nome: "); err != nil {
		return in, err
	}
	if in.Username, err = p.Line("usuário: "); err != nil {
		return in, err
	}
	length, err := p.Line("comprimento (20): ")
	if err != nil {
		return in, err
	}
	n := generator.Default
	if length = strings.TrimSpace(length); length != "" {
		if n, err = strconv.Atoi(length); err != nil {
			return in, vaulterrors.ErrGenLength
		}
	}
	if in.Password, err = gen(n); err != nil {
		return in, err
	}
	if in.URL, err = p.Line("url: "); err != nil {
		return in, err
	}
	in.Notes, err = p.Line("notas: ")
	return in, err
}
