package router

import (
	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/keys"
	"github.com/guialves50/password-manager/src/modules/auth/register/controllers"
	"github.com/guialves50/password-manager/src/modules/auth/register/services"
)

func Routes(c *api.Client) map[string]cli.Command {
	svc := &services.Service{API: c, Params: keys.DefaultParams}
	return map[string]cli.Command{"register": controllers.New(svc.Register)}
}
