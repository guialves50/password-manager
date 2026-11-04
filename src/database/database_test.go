//go:build integration

package database

import (
	"testing"

	"gorm.io/gorm/logger"
)

func TestConnectDiscardsGormLogs(t *testing.T) {
	db, err := Connect()
	if err != nil {
		t.Fatal(err)
	}
	if db.Config.Logger != logger.Discard {
		t.Fatalf("gorm logger is %T, want logger.Discard", db.Config.Logger)
	}
}
