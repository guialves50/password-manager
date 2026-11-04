package router

import (
	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/vault/items/controllers"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
	"github.com/guialves50/password-manager/src/modules/vault/items/services"
	"gorm.io/gorm"
)

func Routes(db *gorm.DB) map[string]cli.SessionCommand {
	repo := repository.New(db)
	get := &services.GetService{Repo: repo}
	return map[string]cli.SessionCommand{
		"add":    controllers.NewAdd((&services.AddService{Repo: repo}).Add),
		"list":   controllers.NewList((&services.ListService{Repo: repo}).List),
		"get":    controllers.NewGet(get.Get),
		"delete": controllers.NewDelete(get.Get, (&services.DeleteService{Repo: repo}).Delete),
	}
}
