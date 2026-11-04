package router

import "testing"

func TestRoutes(t *testing.T) {
	r := Routes(nil)
	if len(r) != 4 || r["add"] == nil || r["list"] == nil || r["get"] == nil || r["delete"] == nil {
		t.Fatalf("routes %v", r)
	}
}
