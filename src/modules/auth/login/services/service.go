package services

import (
	"context"
	"errors"

	"github.com/guialves50/password-manager/src/cli"
	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/dto"
	"github.com/guialves50/password-manager/src/modules/auth/policy"
	prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"
)

type authAPI interface {
	Prelogin(ctx context.Context, email string) (prelogin.Response, error)
	Login(ctx context.Context, req dto.Request) (dto.Response, error)
}

type Service struct {
	API authAPI
}

func (s *Service) Login(ctx context.Context, in dto.Input) (*cli.Session, error) {
	defer keys.Zero(in.Password)

	email, err := policy.NormalizeEmail(in.Email)
	if err != nil {
		return nil, autherrors.ErrInvalidCredentials
	}
	pre, err := s.API.Prelogin(ctx, email)
	if err != nil {
		return nil, err
	}
	master := keys.Derive(in.Password, pre.MasterSalt, keys.Params{Time: pre.KDF.Time, MemoryKiB: pre.KDF.MemoryKiB, Threads: pre.KDF.Threads})
	defer keys.Zero(master)
	authHash, encKey, err := keys.Split(master)
	if err != nil {
		return nil, err
	}
	defer keys.Zero(authHash)
	defer keys.Zero(encKey)

	req := dto.Request{Email: email, AuthHash: authHash}
	res, err := s.API.Login(ctx, req)
	if errors.Is(err, autherrors.ErrTOTPRequired) && in.Code != nil {
		if req.Code, err = in.Code(); err != nil {
			return nil, err
		}
		res, err = s.API.Login(ctx, req)
	}
	if err != nil {
		return nil, err
	}
	vaultKey, err := keys.Open(encKey, res.MasterBlob, []byte("pm/master/v1|"+email))
	if err != nil {
		return nil, errors.New("login: master blob does not open with the derived key")
	}
	return &cli.Session{UserID: res.UserID, Email: email, VaultKey: vaultKey, Token: res.Token}, nil
}
