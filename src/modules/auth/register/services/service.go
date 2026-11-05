package services

import (
	"bytes"
	"context"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
)

type registrar interface {
	Register(ctx context.Context, req dto.Request) error
}

type Service struct {
	API    registrar
	Params keys.Params
}

func (s *Service) Register(ctx context.Context, in dto.Input) (dto.Output, error) {
	defer keys.Zero(in.Password)
	defer keys.Zero(in.Confirm)

	email, err := policy.NormalizeEmail(in.Email)
	if err != nil {
		return dto.Output{}, err
	}
	if err := policy.CheckMasterPassword(in.Password); err != nil {
		return dto.Output{}, err
	}
	if !bytes.Equal(in.Password, in.Confirm) {
		return dto.Output{}, autherrors.ErrPasswordMismatch
	}

	vaultKey, err := keys.Random(32)
	if err != nil {
		return dto.Output{}, err
	}
	defer keys.Zero(vaultKey)
	masterSalt, err := keys.Random(16)
	if err != nil {
		return dto.Output{}, err
	}
	recoverySalt, err := keys.Random(16)
	if err != nil {
		return dto.Output{}, err
	}
	recoveryKey, err := keys.NewRecoveryKey()
	if err != nil {
		return dto.Output{}, err
	}
	recoverySecret := keys.NormalizeRecoveryKey([]byte(recoveryKey))
	defer keys.Zero(recoverySecret)

	masterBlob, authHash, err := keys.Wrap(in.Password, masterSalt, s.Params, vaultKey, []byte("pm/master/v1|"+email))
	if err != nil {
		return dto.Output{}, err
	}
	defer keys.Zero(authHash)
	recoveryBlob, recoveryAuthHash, err := keys.Wrap(recoverySecret, recoverySalt, s.Params, vaultKey, []byte("pm/recovery/v1|"+email))
	if err != nil {
		return dto.Output{}, err
	}
	defer keys.Zero(recoveryAuthHash)

	err = s.API.Register(ctx, dto.Request{
		Email:            email,
		KDF:              prelogin.KDF{Time: s.Params.Time, MemoryKiB: s.Params.MemoryKiB, Threads: s.Params.Threads},
		MasterSalt:       masterSalt,
		MasterBlob:       masterBlob,
		AuthHash:         authHash,
		RecoverySalt:     recoverySalt,
		RecoveryBlob:     recoveryBlob,
		RecoveryAuthHash: recoveryAuthHash,
	})
	if err != nil {
		return dto.Output{}, err
	}
	return dto.Output{RecoveryKey: recoveryKey}, nil
}
