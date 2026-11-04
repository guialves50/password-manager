package services

import (
	"context"
	"time"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	"github.com/guialves50/password-manager/src/modules/user"
)

type userStore interface {
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	RecordFailure(ctx context.Context, id uint64) error
	ResetFailures(ctx context.Context, id uint64) error
}

type DBService struct {
	Repo   userStore
	Params keys.Params
	Derive func(secret, salt []byte, p keys.Params) []byte
}

func (s *DBService) Login(ctx context.Context, in dto.Input) (*cli.Session, error) {
	defer keys.Zero(in.Password)

	email, err := policy.NormalizeEmail(in.Email)
	if err != nil {
		return nil, s.dummy(in.Password)
	}
	u, err := s.Repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, s.dummy(in.Password)
	}
	if d := u.LockedFor(time.Now()); d > 0 {
		return nil, &autherrors.LockedError{Minutes: int((d + time.Minute - 1) / time.Minute)}
	}

	kek := s.Derive(in.Password, u.MasterSalt, keys.Params{Time: u.KDFTime, MemoryKiB: u.KDFMemoryKiB, Threads: u.KDFThreads})
	defer keys.Zero(kek)
	vaultKey, err := keys.Open(kek, u.MasterWrappedKey, []byte("pm/master/v1|"+u.Email))
	if err != nil {
		if err := s.Repo.RecordFailure(ctx, u.ID); err != nil {
			return nil, err
		}
		return nil, autherrors.ErrInvalidCredentials
	}
	if err := s.Repo.ResetFailures(ctx, u.ID); err != nil {
		keys.Zero(vaultKey)
		return nil, err
	}
	return &cli.Session{UserID: u.ID, Email: u.Email, VaultKey: vaultKey}, nil
}

func (s *DBService) dummy(password []byte) error {
	keys.Zero(s.Derive(password, make([]byte, 16), s.Params))
	return autherrors.ErrInvalidCredentials
}
