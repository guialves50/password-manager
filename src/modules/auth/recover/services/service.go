package services

import (
	"bytes"
	"context"
	"errors"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
)

type recoverAPI interface {
	Prelogin(ctx context.Context, email string) (prelogin.Response, error)
	RecoverStart(ctx context.Context, req dto.StartRequest) (dto.StartResponse, error)
	RecoverFinish(ctx context.Context, req dto.FinishRequest) error
}

type Service struct {
	API recoverAPI
}

func (s *Service) Recover(ctx context.Context, in dto.Input) (dto.Output, error) {
	defer keys.Zero(in.RecoveryKey)
	defer keys.Zero(in.Password)
	defer keys.Zero(in.Confirm)

	if err := policy.CheckMasterPassword(in.Password); err != nil {
		return dto.Output{}, err
	}
	if !bytes.Equal(in.Password, in.Confirm) {
		return dto.Output{}, autherrors.ErrPasswordMismatch
	}

	secret := keys.NormalizeRecoveryKey(in.RecoveryKey)
	defer keys.Zero(secret)

	email, err := policy.NormalizeEmail(in.Email)
	if err != nil {
		return dto.Output{}, autherrors.ErrInvalidRecovery
	}
	pre, err := s.API.Prelogin(ctx, email)
	if err != nil {
		return dto.Output{}, err
	}
	params := keys.Params{Time: pre.KDF.Time, MemoryKiB: pre.KDF.MemoryKiB, Threads: pre.KDF.Threads}

	recMaster := keys.Derive(secret, pre.RecoverySalt, params)
	defer keys.Zero(recMaster)
	recAuth, recEnc, err := keys.Split(recMaster)
	if err != nil {
		return dto.Output{}, err
	}
	defer keys.Zero(recAuth)
	defer keys.Zero(recEnc)

	start, err := s.API.RecoverStart(ctx, dto.StartRequest{Email: email, RecoveryAuthHash: recAuth})
	if err != nil {
		return dto.Output{}, err
	}
	vaultKey, err := keys.Open(recEnc, start.RecoveryBlob, []byte("pm/recovery/v1|"+email))
	if err != nil {
		return dto.Output{}, errors.New("recover: recovery blob does not open with the derived key")
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
	newSecret := keys.NormalizeRecoveryKey([]byte(recoveryKey))
	defer keys.Zero(newSecret)

	masterBlob, authHash, err := keys.Wrap(in.Password, masterSalt, params, vaultKey, []byte("pm/master/v1|"+email))
	if err != nil {
		return dto.Output{}, err
	}
	defer keys.Zero(authHash)
	recoveryBlob, newRecAuth, err := keys.Wrap(newSecret, recoverySalt, params, vaultKey, []byte("pm/recovery/v1|"+email))
	if err != nil {
		return dto.Output{}, err
	}
	defer keys.Zero(newRecAuth)

	err = s.API.RecoverFinish(ctx, dto.FinishRequest{
		Email:               email,
		RecoveryAuthHash:    recAuth,
		MasterSalt:          masterSalt,
		MasterBlob:          masterBlob,
		AuthHash:            authHash,
		RecoverySalt:        recoverySalt,
		RecoveryBlob:        recoveryBlob,
		NewRecoveryAuthHash: newRecAuth,
	})
	if err != nil {
		return dto.Output{}, err
	}
	return dto.Output{RecoveryKey: recoveryKey}, nil
}
