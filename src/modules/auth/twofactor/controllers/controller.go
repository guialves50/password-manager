package controllers

import (
	"context"
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/twofactor/dto"
)

type SetupFunc func(ctx context.Context, s *cli.Session) (dto.SetupResponse, error)

type ConfirmFunc func(ctx context.Context, s *cli.Session, code string) error

func New(setup SetupFunc, confirm ConfirmFunc) cli.SessionCommand {
	return func(ctx context.Context, p *cli.Prompter, s *cli.Session, _ string) error {
		err := run(ctx, p, s, setup, confirm)
		if err != nil {
			show(p, nil)
			fmt.Fprintln(p.Out, autherrors.Message(err))
			return err
		}
		fmt.Fprintln(p.Out, "2FA ativado")
		if p.ShowCheck != nil {
			p.ShowCheck()
		}
		return nil
	}
}

func run(ctx context.Context, p *cli.Prompter, s *cli.Session, setup SetupFunc, confirm ConfirmFunc) error {
	res, err := setup(ctx, s)
	if err != nil {
		return err
	}
	lines, err := QR(res.URI)
	if err != nil {
		return err
	}
	show(p, append(lines, "", "chave: "+res.Secret))
	code, err := p.Line("código 2FA: ")
	if err != nil {
		return err
	}
	return confirm(ctx, s, strings.TrimSpace(code))
}

func show(p *cli.Prompter, lines []string) {
	if p.ShowArt != nil {
		p.ShowArt(lines)
		return
	}
	for _, l := range lines {
		fmt.Fprintln(p.Out, l)
	}
}

const (
	dark  = 16
	light = 231
	quiet = 2
)

// QR draws one module per column and two per row with "▀", using fixed
// black/white colors so it scans on dark and light terminals alike.
func QR(content string) ([]string, error) {
	q, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		return nil, err
	}
	q.DisableBorder = true
	bm := q.Bitmap()
	n := len(bm) + 2*quiet
	color := func(y, x int) int {
		y, x = y-quiet, x-quiet
		if y >= 0 && x >= 0 && y < len(bm) && x < len(bm) && bm[y][x] {
			return dark
		}
		return light
	}
	var lines []string
	for y := 0; y < n; y += 2 {
		var b strings.Builder
		for x := range n {
			fmt.Fprintf(&b, "\x1b[38;5;%dm\x1b[48;5;%dm▀", color(y, x), color(y+1, x))
		}
		b.WriteString("\x1b[0m")
		lines = append(lines, b.String())
	}
	return lines, nil
}
