package services

import (
	"bytes"
	"context"
	"time"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/auth/recover/dto"
	"github.com/guialves50/password-manager/src/modules/user"
)

type userStore interface {
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	RecordFailure(ctx context.Context, id uint64) error
	RotateKeys(ctx context.Context, id uint64, verifiedRecoveryBlob, masterSalt, masterBlob, recoverySalt, recoveryBlob []byte) error
}

type DBService struct {
	Repo   userStore
	Params keys.Params
	Derive func(secret, salt []byte, p keys.Params) []byte
}

func (s *DBService) Recover(ctx context.Context, in dto.Input) (dto.Output, error) {
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
		return dto.Output{}, s.dummy(secret)
	}
	u, err := s.Repo.FindByEmail(ctx, email)
	if err != nil {
		return dto.Output{}, err
	}
	if u == nil {
		return dto.Output{}, s.dummy(secret)
	}
	if d := u.LockedFor(time.Now()); d > 0 {
		return dto.Output{}, &autherrors.LockedError{Minutes: int((d + time.Minute - 1) / time.Minute)}
	}

	params := keys.Params{Time: u.KDFTime, MemoryKiB: u.KDFMemoryKiB, Threads: u.KDFThreads}
	oldKEK := s.Derive(secret, u.RecoverySalt, params)
	defer keys.Zero(oldKEK)
	vaultKey, err := keys.Open(oldKEK, u.RecoveryWrappedKey, []byte("pm/recovery/v1|"+u.Email))
	if err != nil {
		if err := s.Repo.RecordFailure(ctx, u.ID); err != nil {
			return dto.Output{}, err
		}
		return dto.Output{}, autherrors.ErrInvalidRecovery
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

	masterKEK := s.Derive(in.Password, masterSalt, params)
	defer keys.Zero(masterKEK)
	recoveryKEK := s.Derive(newSecret, recoverySalt, params)
	defer keys.Zero(recoveryKEK)

	masterBlob, err := keys.Seal(masterKEK, vaultKey, []byte("pm/master/v1|"+u.Email))
	if err != nil {
		return dto.Output{}, err
	}
	recoveryBlob, err := keys.Seal(recoveryKEK, vaultKey, []byte("pm/recovery/v1|"+u.Email))
	if err != nil {
		return dto.Output{}, err
	}
	if err := s.Repo.RotateKeys(ctx, u.ID, u.RecoveryWrappedKey, masterSalt, masterBlob, recoverySalt, recoveryBlob); err != nil {
		return dto.Output{}, err
	}
	return dto.Output{RecoveryKey: recoveryKey}, nil
}

func (s *DBService) dummy(secret []byte) error {
	keys.Zero(s.Derive(secret, make([]byte, 16), s.Params))
	return autherrors.ErrInvalidRecovery
}
