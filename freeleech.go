package main

import "time"

// FreeleechManager centralizes freeleech decisions.
type FreeleechManager struct{}

// global instance used across handlers
var flManager = &FreeleechManager{}

// Sitewide returns true if sitewide freeleech is active (config flag or settings window).
func (m *FreeleechManager) Sitewide() bool {
	if config == nil {
		return false
	}
	// Fast path: config flag
	if config.SitewideFreeleech {
		return true
	}
	// Settings window (best-effort)
	if db != nil {
		open, _, to, has, err := db.LoadFreeleechWindow()
		if err == nil && has && open && time.Now().Before(to) {
			return true
		}
	}
	return false
}

// IsFreeleech returns true if this infohash should be treated as freeleech now.
func (m *FreeleechManager) IsFreeleech(ih [20]byte) bool {
	if m.Sitewide() {
		return true
	}
	if torrentStats == nil {
		return false
	}
	ts, ok := torrentStats.Get(ih)
	if !ok {
		return false
	}
	if ts.Frileech {
		return true
	}
	if config != nil && config.ForceFLNewAndArchive && (ts.Section == "new" || ts.Section == "archive") {
		return true
	}
	if config != nil && config.Freeleech24h && (ts.Section == "new" || ts.Section == "archive") && !ts.Added.IsZero() {
		if time.Since(ts.Added) < 24*time.Hour {
			return true
		}
	}
	return false
}
