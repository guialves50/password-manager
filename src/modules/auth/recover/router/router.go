package router

import (
	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/recover/controllers"
	"github.com/guialves50/password-manager/src/modules/auth/recover/services"
)

func Routes(c *api.Client) map[string]cli.Command {
	svc := &services.Service{API: c}
	return map[string]cli.Command{"recover": controllers.New(svc.Recover)}
}
