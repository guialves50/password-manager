package errors

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidEmail       = errors.New("email inválido")
	ErrPasswordLength     = errors.New("a senha mestra deve ter entre 8 e 128 caracteres")
	ErrPasswordCase       = errors.New("a senha mestra deve conter letras maiúsculas e minúsculas")
	ErrPasswordMismatch   = errors.New("as senhas não conferem")
	ErrEmailTaken         = errors.New("email já cadastrado")
	ErrInvalidCredentials = errors.New("email ou senha mestra inválidos")
	ErrInvalidRecovery    = errors.New("email ou chave de recuperação inválidos")
	ErrUnreachable        = errors.New("não foi possível conectar ao servidor")
	ErrSessionExpired     = errors.New("sessão expirada, faça login novamente")
	ErrInsecureServer     = errors.New("use https para servidores fora do localhost")
)

type LockedError struct {
	Minutes int
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("conta bloqueada, tente novamente em %d minutos", e.Minutes)
}

var known = []error{ErrInvalidEmail, ErrPasswordLength, ErrPasswordCase, ErrPasswordMismatch, ErrEmailTaken, ErrInvalidCredentials, ErrInvalidRecovery, ErrUnreachable, ErrSessionExpired, ErrInsecureServer}

func Message(err error) string {
	var locked *LockedError
	switch {
	case errors.Is(err, io.EOF):
		return "operação cancelada"
	case errors.As(err, &locked):
		return locked.Error()
	}
	for _, k := range known {
		if errors.Is(err, k) {
			return k.Error()
		}
	}
	return "erro interno"
}
