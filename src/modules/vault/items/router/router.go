package router

import (
	"context"

	"github.com/guialves50/password-manager/src/cli"
	"github.com/guialves50/password-manager/src/modules/vault/items/controllers"
	"github.com/guialves50/password-manager/src/modules/vault/items/dto"
	"github.com/guialves50/password-manager/src/modules/vault/items/repository"
	"github.com/guialves50/password-manager/src/modules/vault/items/services"
	"gorm.io/gorm"
)

type store struct {
	repo *repository.Repository
}

func (s store) ListItems(ctx context.Context, sess *cli.Session) ([]dto.StoredItem, error) {
	rows, err := s.repo.ListByUser(ctx, sess.UserID)
	items := make([]dto.StoredItem, len(rows))
	for i, r := range rows {
		items[i] = dto.StoredItem{ID: r.ID, Blob: r.Blob}
	}
	return items, err
}

func (s store) CreateItem(ctx context.Context, sess *cli.Session, id string, blob []byte) error {
	return s.repo.Create(ctx, &repository.Item{ID: id, UserID: sess.UserID, Blob: blob})
}

func (s store) DeleteItem(ctx context.Context, sess *cli.Session, id string) (bool, error) {
	return s.repo.Delete(ctx, sess.UserID, id)
}

func Routes(db *gorm.DB) map[string]cli.SessionCommand {
	repo := store{repository.New(db)}
	get := &services.GetService{Repo: repo}
	return map[string]cli.SessionCommand{
		"add":    controllers.NewAdd((&services.AddService{Repo: repo}).Add),
		"list":   controllers.NewList((&services.ListService{Repo: repo}).List),
		"get":    controllers.NewGet(get.Get),
		"delete": controllers.NewDelete(get.Get, (&services.DeleteService{Repo: repo}).Delete),
	}
}
