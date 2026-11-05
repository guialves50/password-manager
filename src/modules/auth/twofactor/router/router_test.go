package router

import (
	"testing"

	"github.com/guialves50/password-manager/src/api"
)

func TestRoutes(t *testing.T) {
	r := Routes(&api.Client{})
	if len(r) != 1 || r["2fa"] == nil {
		t.Fatalf("routes %v", r)
	}
}
