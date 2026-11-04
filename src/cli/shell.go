package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/guialves50/password-manager/src/modules/auth/keys"
)

type Session struct {
	UserID   uint64
	Email    string
	VaultKey []byte
}

func (s *Session) Close() {
	keys.Zero(s.VaultKey)
}

type SessionCommand func(ctx context.Context, p *Prompter, s *Session, arg string) error

func Shell(ctx context.Context, p *Prompter, s *Session, cmds map[string]SessionCommand) {
	defer s.Close()
	for {
		fmt.Fprint(p.Out, "pm> ")
		line, err := p.In.ReadString('\n')
		line = strings.TrimSpace(line)
		name, arg, _ := strings.Cut(line, " ")
		switch {
		case line == "exit" || line == "logout":
			return
		case cmds[name] != nil:
			if errors.Is(cmds[name](ctx, p, s, strings.TrimSpace(arg)), io.EOF) {
				return
			}
		case line != "":
			fmt.Fprintln(p.Out, "comando desconhecido")
		}
		if err != nil {
			fmt.Fprintln(p.Out)
			return
		}
	}
}
