package totp

import (
	"sync"
	"time"
)

// ponytail: in-memory per process; resets on restart and isn't shared between
// server instances. Move to the database if the server is ever replicated.
type Limiter struct {
	mu  sync.Mutex
	m   map[string]*ipEntry
	now func() time.Time
}

type ipEntry struct {
	fails        int
	since, until time.Time
}

func NewLimiter(now func() time.Time) *Limiter {
	return &Limiter{m: map[string]*ipEntry{}, now: now}
}

func (l *Limiter) LockedFor(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[ip]; e != nil {
		return max(0, e.until.Sub(l.now()))
	}
	return 0
}

func (l *Limiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.m) > 10000 {
		for k, e := range l.m {
			if l.stale(e, now) {
				delete(l.m, k)
			}
		}
	}
	e := l.m[ip]
	if e == nil || l.stale(e, now) {
		e = &ipEntry{since: now}
		l.m[ip] = e
	}
	if e.fails++; e.fails >= MaxFailures {
		e.until = now.Add(LockDuration)
	}
}

func (l *Limiter) stale(e *ipEntry, now time.Time) bool {
	return !now.Before(e.since.Add(LockDuration)) && !now.Before(e.until)
}
