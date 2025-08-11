package main

import (
	"strings"
	"sync"
	"time"
)

type User struct {
	ID          int
	Passkey     string
	Enabled     bool
	DownloadBan bool
}

type UserCache struct {
	mu    sync.RWMutex
	users map[string]*User // passkey -> user
	ttl   int
	db    *DB
}

func NewUserCache(ttl int, db *DB) *UserCache {
	return &UserCache{
		users: make(map[string]*User),
		ttl:   ttl,
		db:    db,
	}
}

func (c *UserCache) RefreshLoop() {
	for {
		_ = c.Refresh()
		time.Sleep(time.Duration(c.ttl) * time.Second)
	}
}

func (c *UserCache) Refresh() error {
	users, err := c.db.LoadUsers()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.users = users
	c.mu.Unlock()
	return nil
}

func (c *UserCache) Count() int {
	c.mu.RLock()
	n := len(c.users)
	c.mu.RUnlock()
	return n
}

func (c *UserCache) Get(passkey string) (*User, bool) {
	c.mu.RLock()
	u, ok := c.users[passkey]
	c.mu.RUnlock()
	return u, ok
}

func (c *UserCache) GetOrFetch(passkey string) (*User, bool) {
	if u, ok := c.Get(passkey); ok {
		return u, true
	}
	u, err := c.db.GetUserByPasskey(passkey)
	if err != nil || u == nil {
		return nil, false
	}
	c.mu.Lock()
	c.users[passkey] = u
	c.mu.Unlock()
	return u, true
}

// User agent ban logic: substring match
func IsUserAgentBanned(ua string) bool {
	if config == nil || ua == "" {
		return false
	}
	for _, banned := range config.UserAgentBan {
		if banned != "" && strings.Contains(ua, banned) {
			return true
		}
	}
	return false
}
