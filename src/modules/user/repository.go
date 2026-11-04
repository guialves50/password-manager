package user

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) FindByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *Repository) RecordFailure(ctx context.Context, id uint64) error {
	return r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).Updates(map[string]any{
		"failed_attempts": gorm.Expr("failed_attempts + 1"),
		"locked_until":    gorm.Expr("CASE WHEN failed_attempts + 1 >= ? THEN ?::timestamptz ELSE locked_until END", MaxFailedAttempts, time.Now().Add(LockDuration)),
	}).Error
}

func (r *Repository) ResetFailures(ctx context.Context, id uint64) error {
	return r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).Updates(map[string]any{
		"failed_attempts": 0,
		"locked_until":    nil,
	}).Error
}
