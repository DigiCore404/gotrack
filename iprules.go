package main

import (
	"sync"
	"time"
)

type IPRules struct {
	mu       sync.RWMutex
	db       *DB
	staticWL map[string]struct{}
	staticBL map[string]struct{}
	dynBL    map[string]struct{}
}

func NewIPRules(db *DB, cfg *Config) *IPRules {
	r := &IPRules{
		db:       db,
		staticWL: make(map[string]struct{}),
		staticBL: make(map[string]struct{}),
		dynBL:    make(map[string]struct{}),
	}
	for _, ip := range cfg.IPWhitelist {
		r.staticWL[ip] = struct{}{}
	}
	for _, ip := range cfg.IPBanlist {
		r.staticBL[ip] = struct{}{}
	}
	return r
}

func (r *IPRules) Refresh() error {
	list, err := r.db.LoadIPBans()
	if err != nil {
		return err
	}
	m := make(map[string]struct{}, len(list))
	for _, ip := range list {
		m[ip] = struct{}{}
	}
	r.mu.Lock()
	r.dynBL = m
	r.mu.Unlock()
	return nil
}

func (r *IPRules) RefreshLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		_ = r.Refresh()
	}
}

func (r *IPRules) IsAllowed(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, bad := r.dynBL[ip]; bad {
		return false
	}
	if _, bad := r.staticBL[ip]; bad {
		return false
	}
	if len(r.staticWL) > 0 {
		_, ok := r.staticWL[ip]
		return ok
	}
	return true
}

func (r *IPRules) DynamicCount() int {
	r.mu.RLock()
	n := len(r.dynBL)
	r.mu.RUnlock()
	return n
}
