package router

import (
	"context"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/recover/controllers"
	"github.com/guialves50/password-manager/src/modules/auth/recover/repository"
	"github.com/guialves50/password-manager/src/modules/auth/recover/services"
	"github.com/guialves50/password-manager/src/modules/user"
	"gorm.io/gorm"
)

type store struct {
	*user.Repository
	rotator *repository.Repository
}

func (s store) RotateKeys(ctx context.Context, id uint64, masterSalt, masterBlob, recoverySalt, recoveryBlob []byte) error {
	return s.rotator.RotateKeys(ctx, id, masterSalt, masterBlob, recoverySalt, recoveryBlob)
}

func Routes(db *gorm.DB) map[string]cli.Command {
	svc := &services.Service{Repo: store{user.NewRepository(db), repository.New(db)}, Params: keys.DefaultParams, Derive: keys.Derive}
	return map[string]cli.Command{"recover": controllers.New(svc.Recover)}
}
