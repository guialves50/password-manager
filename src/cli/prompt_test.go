package cli

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestLine(t *testing.T) {
	var out bytes.Buffer
	p := &Prompter{In: bufio.NewReader(strings.NewReader("a@b.com\r\nsegunda\n")), Out: &out}
	got, err := p.Line("email: ")
	if err != nil || got != "a@b.com" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = p.Line("x: ")
	if err != nil || got != "segunda" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := p.Line("y: "); err != io.EOF {
		t.Fatalf("want io.EOF, got %v", err)
	}
	if out.String() != "email: x: y: " {
		t.Fatalf("out %q", out.String())
	}
}

func TestSecretHidesValue(t *testing.T) {
	var out bytes.Buffer
	p := &Prompter{Out: &out, ReadSecret: func() ([]byte, error) { return []byte("Segredo123"), nil }}
	got, err := p.Secret("senha mestra: ")
	if err != nil || string(got) != "Segredo123" {
		t.Fatalf("got %q, %v", got, err)
	}
	if !strings.HasPrefix(out.String(), "senha mestra: ") || strings.Contains(out.String(), "Segredo123") {
		t.Fatalf("out %q", out.String())
	}
}

func TestSecretEOF(t *testing.T) {
	p := &Prompter{Out: io.Discard, ReadSecret: func() ([]byte, error) { return nil, io.EOF }}
	if _, err := p.Secret("senha: "); err != io.EOF {
		t.Fatalf("want io.EOF, got %v", err)
	}
}
