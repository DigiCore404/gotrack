package main

import (
	"encoding/hex"
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

// Overwrite the cached entry entirely
func (ts *TorrentStats) Set(key [20]byte, v TorrentStat) {
	ts.mu.Lock()
	ts.data[key] = v
	ts.mu.Unlock()
}

// Update only meta fields (ID/Section/Size) without clobbering live counters
func (ts *TorrentStats) SetMeta(key [20]byte, id int, section string, size uint64) {
	ts.mu.Lock()
	cur := ts.data[key] // zero value if not present
	cur.ID = id
	cur.Section = section
	if size > 0 {
		cur.Size = size
	}
	ts.data[key] = cur
	ts.mu.Unlock()
}

// Convenience: set by hex infohash
func (ts *TorrentStats) SetHex(ihHex string, v TorrentStat) {
	b, err := hex.DecodeString(ihHex)
	if err != nil || len(b) != 20 {
		return
	}
	var k [20]byte
	copy(k[:], b)
	ts.Set(k, v)
}
