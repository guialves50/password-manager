package services

import (
	"bytes"
	"context"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/auth/register/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

type creator interface {
	Create(ctx context.Context, u *user.User) error
}

type Service struct {
	Repo   creator
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
	recoverySecret := keys.NormalizeRecoveryKey(recoveryKey)
	defer keys.Zero(recoverySecret)

	masterKEK := keys.Derive(in.Password, masterSalt, s.Params)
	defer keys.Zero(masterKEK)
	recoveryKEK := keys.Derive(recoverySecret, recoverySalt, s.Params)
	defer keys.Zero(recoveryKEK)

	masterBlob, err := keys.Seal(masterKEK, vaultKey, []byte("pm/master/v1|"+email))
	if err != nil {
		return dto.Output{}, err
	}
	recoveryBlob, err := keys.Seal(recoveryKEK, vaultKey, []byte("pm/recovery/v1|"+email))
	if err != nil {
		return dto.Output{}, err
	}

	u := &user.User{
		Email:              email,
		KDFTime:            s.Params.Time,
		KDFMemoryKiB:       s.Params.MemoryKiB,
		KDFThreads:         s.Params.Threads,
		MasterSalt:         masterSalt,
		MasterWrappedKey:   masterBlob,
		RecoverySalt:       recoverySalt,
		RecoveryWrappedKey: recoveryBlob,
	}
	if err := s.Repo.Create(ctx, u); err != nil {
		return dto.Output{}, err
	}
	return dto.Output{RecoveryKey: recoveryKey}, nil
}
