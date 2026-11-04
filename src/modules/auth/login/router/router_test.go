package router

import "testing"

func TestRoutes(t *testing.T) {
	r := Routes(nil, nil)
	if len(r) != 1 || r["login"] == nil {
		t.Fatalf("routes %v", r)
	}
}
