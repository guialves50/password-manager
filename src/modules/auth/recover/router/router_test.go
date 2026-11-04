package router

import "testing"

func TestRoutes(t *testing.T) {
	r := Routes(nil)
	if len(r) != 1 || r["recover"] == nil {
		t.Fatalf("routes %v", r)
	}
}
