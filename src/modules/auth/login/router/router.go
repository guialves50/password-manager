package router

import (
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/login/controllers"
	"github.com/guialves50/password-manager/src/modules/auth/login/services"
	"github.com/guialves50/password-manager/src/modules/user"
	"gorm.io/gorm"
)

func Routes(db *gorm.DB, cmds map[string]cli.SessionCommand) map[string]cli.Command {
	svc := &services.Service{Repo: user.NewRepository(db), Params: keys.DefaultParams, Derive: keys.Derive}
	return map[string]cli.Command{"login": controllers.New(svc.Login, cmds)}
}
