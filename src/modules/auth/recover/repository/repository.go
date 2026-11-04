package repository

import (
	"context"

	"gorm.io/gorm"

	autherrors "github.com/guialves50/password-manager/src/modules/auth/errors"
	"github.com/guialves50/password-manager/src/modules/session"
	"github.com/guialves50/password-manager/src/modules/user"
)

type Repository struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) RotateAuth(ctx context.Context, id uint64, verifiedRecoveryAuthHash []byte, next *user.User) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&user.User{}).Where("id = ? AND recovery_auth_hash = ?", id, verifiedRecoveryAuthHash).Updates(map[string]any{
			"master_salt":          next.MasterSalt,
			"master_wrapped_key":   next.MasterWrappedKey,
			"auth_salt":            next.AuthSalt,
			"auth_hash":            next.AuthHash,
			"recovery_salt":        next.RecoverySalt,
			"recovery_wrapped_key": next.RecoveryWrappedKey,
			"recovery_auth_salt":   next.RecoveryAuthSalt,
			"recovery_auth_hash":   next.RecoveryAuthHash,
			"failed_attempts":      0,
			"locked_until":         nil,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return autherrors.ErrInvalidRecovery
		}
		return tx.Where("user_id = ?", id).Delete(&session.Session{}).Error
	})
}
