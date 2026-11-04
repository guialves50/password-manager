package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"gorm.io/gorm"

	"github.com/guialves50/password-manager/src/modules/user"
)

const IdleTimeout = 30 * time.Minute

type Session struct {
	TokenHash  []byte    `gorm:"primaryKey"`
	UserID     uint64    `gorm:"not null;index"`
	User       user.User `gorm:"constraint:OnDelete:CASCADE"`
	LastUsedAt time.Time `gorm:"not null"`
	CreatedAt  time.Time
}

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func (r *Repository) Create(ctx context.Context, userID uint64, now time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	s := &Session{TokenHash: hash(token), UserID: userID, LastUsedAt: now, CreatedAt: now}
	if err := r.db.WithContext(ctx).Create(s).Error; err != nil {
		return "", err
	}
	return token, nil
}

func (r *Repository) Touch(ctx context.Context, token string, now time.Time) (uint64, bool, error) {
	var ids []uint64
	err := r.db.WithContext(ctx).Raw(
		"UPDATE sessions SET last_used_at = ? WHERE token_hash = ? AND last_used_at > ? RETURNING user_id",
		now, hash(token), now.Add(-IdleTimeout),
	).Scan(&ids).Error
	if err != nil || len(ids) == 0 {
		return 0, false, err
	}
	return ids[0], true, nil
}

func (r *Repository) Delete(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token_hash = ?", hash(token)).Delete(&Session{}).Error
}

func (r *Repository) PurgeExpired(ctx context.Context, now time.Time) error {
	return r.db.WithContext(ctx).Where("last_used_at <= ?", now.Add(-IdleTimeout)).Delete(&Session{}).Error
}
