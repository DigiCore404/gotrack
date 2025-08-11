package main

import (
	"sync"
	"time"
)

type TorrentStats struct {
	mu   sync.RWMutex
	db   *DB
	data map[[20]byte]TorrentStat
}

func NewTorrentStats(db *DB) *TorrentStats {
	return &TorrentStats{db: db, data: make(map[[20]byte]TorrentStat)}
}

func (ts *TorrentStats) Refresh() error {
	m, err := ts.db.LoadTorrentStats()
	if err != nil {
		return err
	}
	ts.mu.Lock()
	ts.data = m
	ts.mu.Unlock()
	return nil
}

func (ts *TorrentStats) RefreshLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		_ = ts.Refresh()
	}
}

func (ts *TorrentStats) Get(key [20]byte) (TorrentStat, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	v, ok := ts.data[key]
	return v, ok
}

func (ts *TorrentStats) Count() int {
	ts.mu.RLock()
	n := len(ts.data)
	ts.mu.RUnlock()
	return n
}
