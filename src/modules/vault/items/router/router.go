package router

import (
	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/vault/generator"
	"github.com/guialves50/password-manager/src/modules/vault/items/controllers"
	"github.com/guialves50/password-manager/src/modules/vault/items/services"
)

func Routes(c *api.Client) map[string]cli.SessionCommand {
	get := &services.GetService{Repo: c}
	return map[string]cli.SessionCommand{
		"add":    controllers.NewAdd((&services.AddService{Repo: c}).Add, generator.Generate),
		"list":   controllers.NewList((&services.ListService{Repo: c}).List),
		"get":    controllers.NewGet(get.Get),
		"delete": controllers.NewDelete(get.Get, (&services.DeleteService{Repo: c}).Delete),
	}
}
