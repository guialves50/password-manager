package cli

import (
	"bufio"
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

func Shell(in *bufio.Reader, out io.Writer, s *Session) {
	defer s.Close()
	for {
		fmt.Fprint(out, "pm> ")
		line, err := in.ReadString('\n')
		cmd := strings.TrimSpace(line)
		switch {
		case cmd == "exit" || cmd == "logout":
			return
		case cmd != "":
			fmt.Fprintln(out, "comando desconhecido")
		}
		if err != nil {
			fmt.Fprintln(out)
			return
		}
	}
}
