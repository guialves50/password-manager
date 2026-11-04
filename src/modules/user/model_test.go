package user

import (
	"testing"
	"time"
)

func TestLockedFor(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Second)
	future := now.Add(10 * time.Minute)
	cases := []struct {
		until *time.Time
		want  time.Duration
	}{
		{nil, 0},
		{&past, 0},
		{&now, 0},
		{&future, 10 * time.Minute},
	}
	for _, c := range cases {
		u := User{LockedUntil: c.until}
		if got := u.LockedFor(now); got != c.want {
			t.Errorf("until %v: got %v, want %v", c.until, got, c.want)
		}
	}
	if MaxFailedAttempts != 5 || LockDuration != 15*time.Minute {
		t.Fatal("lockout constants differ from spec")
	}
}
