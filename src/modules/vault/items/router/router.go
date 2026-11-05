package router

import (
	"github.com/guialves50/password-manager/src/api"
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/vault/generator"
	"github.com/guialves50/password-manager/src/modules/vault/items/controllers"
	"github.com/guialves50/password-manager/src/modules/vault/items/services"
)

func Routes(c *api.Client) map[string]cli.SessionCommand {
	get, list := &services.GetService{Repo: c}, &services.ListService{Repo: c}
	return map[string]cli.SessionCommand{
		"add":    controllers.NewAdd((&services.AddService{Repo: c}).Add, generator.Generate),
		"list":   controllers.NewList(list.Items),
		"get":    controllers.NewGet(get.Get, list.Items),
		"delete": controllers.NewDelete(get.Get, list.Items, (&services.DeleteService{Repo: c}).Delete),
	}
}
