//go:build integration

package database

import (
	"testing"

	"gorm.io/gorm"
)

func TestTx(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := Connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin: %v", tx.Error)
	}
	t.Cleanup(func() {
		tx.Rollback()
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	return tx
}
