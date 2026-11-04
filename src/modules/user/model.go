package user

import "time"

const (
	MaxFailedAttempts = 5
	LockDuration      = 15 * time.Minute
)

type User struct {
	ID                 uint64 `gorm:"primaryKey"`
	Email              string `gorm:"size:254;not null;uniqueIndex;check:email = lower(email)"`
	KDFTime            uint32 `gorm:"not null"`
	KDFMemoryKiB       uint32 `gorm:"not null"`
	KDFThreads         uint8  `gorm:"not null"`
	MasterSalt         []byte `gorm:"not null"`
	MasterWrappedKey   []byte `gorm:"not null"`
	RecoverySalt       []byte `gorm:"not null"`
	RecoveryWrappedKey []byte `gorm:"not null"`
	FailedAttempts     int    `gorm:"not null;default:0"`
	LockedUntil        *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (u *User) LockedFor(now time.Time) time.Duration {
	if u.LockedUntil == nil || !u.LockedUntil.After(now) {
		return 0
	}
	return u.LockedUntil.Sub(now)
}
