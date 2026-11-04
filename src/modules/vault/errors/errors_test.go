package errors

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestMessages(t *testing.T) {
	cases := map[error]string{
		ErrNameLength:     "o nome deve ter entre 1 e 100 caracteres",
		ErrPasswordLength: "a senha deve ter entre 1 e 1024 caracteres",
		ErrUsernameLength: "usuário excede 254 caracteres",
		ErrURLLength:      "URL excede 2048 caracteres",
		ErrNotesLength:    "notas excedem 4096 caracteres",
		ErrNameTaken:      "já existe um item com esse nome",
		ErrNotFound:       "item não encontrado",
		ErrInvalidText:    "o item contém texto que não é UTF-8 válido",
	}
	for err, want := range cases {
		if got := err.Error(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		if got := Message(fmt.Errorf("x: %w", err)); got != want {
			t.Errorf("Message: got %q, want %q", got, want)
		}
	}
}

func TestMessageFallsBackToAuth(t *testing.T) {
	cases := map[error]string{
		io.EOF:                         "operação cancelada",
		fmt.Errorf("read: %w", io.EOF): "operação cancelada",
		errors.New("pq: segredo"):      "erro interno",
	}
	for err, want := range cases {
		if got := Message(err); got != want {
			t.Errorf("%v: got %q, want %q", err, got, want)
		}
	}
}
