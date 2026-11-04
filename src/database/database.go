package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"time"
)

func Connect() (*gorm.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5433/password_manager?sslmode=disable"
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	type User struct {
		ID        uint   `gorm:"primaryKey"`
		Username  string `gorm:"unique"`
		Email     string `gorm:"unique"`
		Name      string
		Password  string
		CreatedAt time.Time `gorm:"autoCreateTime"`
		UpdatedAt time.Time `gorm:"autoUpdateTime"`
	}
	return db, db.AutoMigrate()
}
