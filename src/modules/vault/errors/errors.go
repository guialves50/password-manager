package errors

import (
	"errors"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
)

var (
	ErrNameLength     = errors.New("o nome deve ter entre 1 e 100 caracteres")
	ErrPasswordLength = errors.New("a senha deve ter entre 1 e 1024 caracteres")
	ErrUsernameLength = errors.New("usuário excede 254 caracteres")
	ErrURLLength      = errors.New("URL excede 2048 caracteres")
	ErrNotesLength    = errors.New("notas excedem 4096 caracteres")
	ErrNameTaken      = errors.New("já existe um item com esse nome")
	ErrNotFound       = errors.New("item não encontrado")
)

var known = []error{ErrNameLength, ErrPasswordLength, ErrUsernameLength, ErrURLLength, ErrNotesLength, ErrNameTaken, ErrNotFound}

func Message(err error) string {
	for _, k := range known {
		if errors.Is(err, k) {
			return k.Error()
		}
	}
	return autherrors.Message(err)
}
