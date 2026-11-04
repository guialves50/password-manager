package router

import (
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/register/controllers"
	"github.com/guialves50/password-manager/src/modules/auth/register/repository"
	"github.com/guialves50/password-manager/src/modules/auth/register/services"
	"gorm.io/gorm"
)

func Routes(db *gorm.DB) map[string]cli.Command {
	svc := &services.DBService{Repo: repository.New(db), Params: keys.DefaultParams}
	return map[string]cli.Command{"register": controllers.New(svc.Register)}
}
