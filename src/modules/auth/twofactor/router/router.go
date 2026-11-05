package router

import (
	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/auth/twofactor/controllers"
)

func Routes(c *api.Client) map[string]cli.SessionCommand {
	return map[string]cli.SessionCommand{"2fa": controllers.New(c.Setup2FA, c.Confirm2FA)}
}
