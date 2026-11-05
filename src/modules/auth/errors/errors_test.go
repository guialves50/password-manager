package errors

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestMessages(t *testing.T) {
	cases := map[error]string{
		ErrInvalidEmail:           "email inválido",
		ErrPasswordLength:         "a senha mestra deve ter entre 8 e 128 caracteres",
		ErrPasswordCase:           "a senha mestra deve conter letras maiúsculas e minúsculas",
		ErrPasswordMismatch:       "as senhas não conferem",
		ErrEmailTaken:             "email já cadastrado",
		ErrInvalidCredentials:     "email ou senha mestra inválidos",
		ErrInvalidRecovery:        "email ou chave de recuperação inválidos",
		ErrUnreachable:            "não foi possível conectar ao servidor",
		ErrSessionExpired:         "sessão expirada, faça login novamente",
		ErrInsecureServer:         "use https para servidores fora do localhost",
		ErrBusy:                   "servidor ocupado, tente novamente em instantes",
		ErrTOTPRequired:           "código 2FA necessário",
		ErrInvalidTOTP:            "código 2FA inválido",
		ErrTOTPEnabled:            "2FA já está ativo",
		ErrNoPendingTOTP:          "rode 2fa novamente",
		&LockedError{Minutes: 15}: "conta bloqueada, tente novamente em 15 minutos",
		&LockedError{Minutes: 1}:  "conta bloqueada, tente novamente em 1 minutos",
	}
	for err, want := range cases {
		if got := err.Error(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestMessage(t *testing.T) {
	cases := map[error]string{
		io.EOF:                                  "operação cancelada",
		fmt.Errorf("read: %w", io.EOF):          "operação cancelada",
		ErrEmailTaken:                           "email já cadastrado",
		ErrInvalidCredentials:                   "email ou senha mestra inválidos",
		fmt.Errorf("x: %w", ErrInvalidRecovery): "email ou chave de recuperação inválidos",
		fmt.Errorf("x: %w", ErrUnreachable):     "não foi possível conectar ao servidor",
		fmt.Errorf("x: %w", ErrSessionExpired):  "sessão expirada, faça login novamente",
		ErrInsecureServer:                       "use https para servidores fora do localhost",
		fmt.Errorf("x: %w", ErrInvalidTOTP):     "código 2FA inválido",
		ErrTOTPEnabled:                          "2FA já está ativo",
		ErrNoPendingTOTP:                        "rode 2fa novamente",
		&LockedError{Minutes: 3}:                "conta bloqueada, tente novamente em 3 minutos",
		errors.New("pq: SenhaForte1"):           "erro interno",
	}
	for err, want := range cases {
		if got := Message(err); got != want {
			t.Errorf("%v: got %q, want %q", err, got, want)
		}
	}
}
