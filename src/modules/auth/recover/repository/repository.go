package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/guialves50/password-manager/src/modules/user"
)

type Repository struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) RotateKeys(ctx context.Context, id uint64, masterSalt, masterBlob, recoverySalt, recoveryBlob []byte) error {
	res := r.db.WithContext(ctx).Model(&user.User{}).Where("id = ?", id).Updates(map[string]any{
		"master_salt":          masterSalt,
		"master_wrapped_key":   masterBlob,
		"recovery_salt":        recoverySalt,
		"recovery_wrapped_key": recoveryBlob,
		"failed_attempts":      0,
		"locked_until":         nil,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
