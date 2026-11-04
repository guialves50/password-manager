package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type Command func(ctx context.Context, p *Prompter) error

type Prompter struct {
	In         *bufio.Reader
	Out        io.Writer
	ReadSecret func() ([]byte, error)
}

func NewTerminalPrompter() *Prompter {
	return &Prompter{
		In:  bufio.NewReader(os.Stdin),
		Out: os.Stdout,
		ReadSecret: func() ([]byte, error) {
			return term.ReadPassword(int(os.Stdin.Fd()))
		},
	}
}

func (p *Prompter) Line(label string) (string, error) {
	fmt.Fprint(p.Out, label)
	s, err := p.In.ReadString('\n')
	if err == io.EOF && s == "" {
		return "", io.EOF
	}
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func (p *Prompter) Secret(label string) ([]byte, error) {
	fmt.Fprint(p.Out, label)
	b, err := p.ReadSecret()
	fmt.Fprintln(p.Out)
	return b, err
}
