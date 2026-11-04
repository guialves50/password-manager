package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
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
		In:         bufio.NewReader(os.Stdin),
		Out:        os.Stdout,
		ReadSecret: readSecret,
	}
}

func readSecret() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sig:
			term.Restore(fd, state)
			fmt.Fprintln(os.Stdout)
			os.Exit(130)
		case <-done:
		}
	}()
	return term.ReadPassword(fd)
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
