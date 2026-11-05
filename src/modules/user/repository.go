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

func (r *Repository) Attempt(ctx context.Context, id uint64) (bool, error) {
	now := time.Now()
	res := r.db.WithContext(ctx).Model(&User{}).Where("id = ? AND (locked_until IS NULL OR locked_until <= ?::timestamptz)", id, now).Updates(map[string]any{
		"failed_attempts": gorm.Expr("CASE WHEN locked_until IS NOT NULL AND locked_until <= ?::timestamptz THEN 1 ELSE failed_attempts + 1 END", now),
		"locked_until":    gorm.Expr("CASE WHEN locked_until IS NOT NULL AND locked_until <= ?::timestamptz THEN NULL WHEN failed_attempts + 1 >= ? THEN ?::timestamptz ELSE locked_until END", now, MaxFailedAttempts, now.Add(LockDuration)),
	})
	return res.RowsAffected == 1, res.Error
}

func (r *Repository) ResetFailures(ctx context.Context, id uint64) error {
	return r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).Updates(map[string]any{
		"failed_attempts": 0,
		"locked_until":    nil,
	}).Error
}

func (r *Repository) FindByID(ctx context.Context, id uint64) (*User, error) {
	var u User
	err := r.db.WithContext(ctx).First(&u, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// SetTOTPPending replaces the pending secret; false when 2FA is already active.
func (r *Repository) SetTOTPPending(ctx context.Context, id uint64, blob []byte) (bool, error) {
	res := r.db.WithContext(ctx).Model(&User{}).Where("id = ? AND totp_secret IS NULL", id).Update("totp_pending", blob)
	return res.RowsAffected == 1, res.Error
}

// TOTPAttempt reserves one code guess before it is checked, so parallel
// guesses can't exceed the limit. False while the 2FA lock is active.
func (r *Repository) TOTPAttempt(ctx context.Context, id uint64, now time.Time) (bool, error) {
	res := r.db.WithContext(ctx).Model(&User{}).Where("id = ? AND (totp_locked_until IS NULL OR totp_locked_until <= ?::timestamptz)", id, now).Updates(map[string]any{
		"totp_failures":     gorm.Expr("CASE WHEN totp_locked_until IS NOT NULL THEN 1 ELSE totp_failures + 1 END"),
		"totp_locked_until": gorm.Expr("CASE WHEN totp_locked_until IS NULL AND totp_failures + 1 >= ? THEN ?::timestamptz END", MaxTOTPFailures, now.Add(TOTPLockDuration)),
	})
	return res.RowsAffected == 1, res.Error
}

// TOTPAccept records the accepted step; false if it (or a later one) was already used.
func (r *Repository) TOTPAccept(ctx context.Context, id uint64, counter int64) (bool, error) {
	res := r.db.WithContext(ctx).Model(&User{}).Where("id = ? AND totp_last_counter < ?", id, counter).Updates(map[string]any{
		"totp_last_counter": counter,
		"totp_failures":     0,
		"totp_locked_until": nil,
	})
	return res.RowsAffected == 1, res.Error
}

func (r *Repository) ActivateTOTP(ctx context.Context, id uint64, counter int64) (bool, error) {
	res := r.db.WithContext(ctx).Model(&User{}).Where("id = ? AND totp_pending IS NOT NULL AND totp_secret IS NULL", id).Updates(map[string]any{
		"totp_secret":       gorm.Expr("totp_pending"),
		"totp_pending":      nil,
		"totp_last_counter": counter,
		"totp_failures":     0,
		"totp_locked_until": nil,
	})
	return res.RowsAffected == 1, res.Error
}
