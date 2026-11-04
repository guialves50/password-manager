package errors

import "testing"

func TestMessages(t *testing.T) {
	cases := map[error]string{
		ErrInvalidEmail:           "email inválido",
		ErrPasswordLength:         "a senha mestra deve ter entre 8 e 128 caracteres",
		ErrPasswordCase:           "a senha mestra deve conter letras maiúsculas e minúsculas",
		ErrPasswordMismatch:       "as senhas não conferem",
		ErrEmailTaken:             "email já cadastrado",
		ErrInvalidCredentials:     "email ou senha mestra inválidos",
		ErrInvalidRecovery:        "email ou chave de recuperação inválidos",
		&LockedError{Minutes: 15}: "conta bloqueada, tente novamente em 15 minutos",
		&LockedError{Minutes: 1}:  "conta bloqueada, tente novamente em 1 minutos",
	}
	for err, want := range cases {
		if got := err.Error(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
