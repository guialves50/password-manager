package router

import (
	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/login/controllers"
	"github.com/guialves50/password-manager/src/modules/auth/login/services"
)

func Routes(c *api.Client, cmds map[string]cli.SessionCommand) map[string]cli.Command {
	svc := &services.Service{API: c}
	return map[string]cli.Command{"login": controllers.New(svc.Login, c.Logout, cmds)}
}
