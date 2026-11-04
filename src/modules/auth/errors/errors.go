package errors

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidEmail       = errors.New("email inválido")
	ErrPasswordLength     = errors.New("a senha mestra deve ter entre 8 e 128 caracteres")
	ErrPasswordCase       = errors.New("a senha mestra deve conter letras maiúsculas e minúsculas")
	ErrPasswordMismatch   = errors.New("as senhas não conferem")
	ErrEmailTaken         = errors.New("email já cadastrado")
	ErrInvalidCredentials = errors.New("email ou senha mestra inválidos")
	ErrInvalidRecovery    = errors.New("email ou chave de recuperação inválidos")
)

type LockedError struct {
	Minutes int
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("conta bloqueada, tente novamente em %d minutos", e.Minutes)
}
