package repository

import (
	"context"

	"gorm.io/gorm"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/user"
)

type Repository struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) RotateKeys(ctx context.Context, id uint64, verifiedRecoveryBlob, masterSalt, masterBlob, recoverySalt, recoveryBlob []byte) error {
	res := r.db.WithContext(ctx).Model(&user.User{}).Where("id = ? AND recovery_wrapped_key = ?", id, verifiedRecoveryBlob).Updates(map[string]any{
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
		return autherrors.ErrInvalidRecovery
	}
	return nil
}
