package repository

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/guialves50/password-manager/src/modules/user"
)

type Item struct {
	ID        string    `gorm:"primaryKey;size:32"`
	UserID    uint64    `gorm:"not null;index"`
	User      user.User `gorm:"constraint:OnDelete:CASCADE"`
	Blob      []byte    `gorm:"not null"`
	CreatedAt time.Time
}

func (Item) TableName() string {
	return "vault_items"
}

type Repository struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, it *Item) error {
	return r.db.WithContext(ctx).Create(it).Error
}

func (r *Repository) ListByUser(ctx context.Context, userID uint64) ([]Item, error) {
	var items []Item
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at, id").Find(&items).Error
	return items, err
}

func (r *Repository) Delete(ctx context.Context, userID uint64, id string) (bool, error) {
	res := r.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&Item{})
	return res.RowsAffected > 0, res.Error
}
