package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GET /stats  (ADMIN-ONLY)
func StatsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	type summary struct {
		UptimeSeconds int64  `json:"uptime_seconds"`
		StartedAt     string `json:"started_at"`
		Torrents      int    `json:"torrents"`
		Peers         int    `json:"peers"`
		Seeders       int    `json:"seeders"`
		Leechers      int    `json:"leechers"`
		SafeMode      bool   `json:"safe_mode"`
		SitewideFL    bool   `json:"sitewide_freeleech"`
	}

	t, p, s, l := peerStore.Counts()
	resp := summary{
		UptimeSeconds: time.Since(startTime).Round(time.Second).Milliseconds() / 1000,
		StartedAt:     startTime.UTC().Format(time.RFC3339),
		Torrents:      t,
		Peers:         p,
		Seeders:       s,
		Leechers:      l,
		SafeMode:      config.SafeMode,
		SitewideFL:    flManager.Sitewide(),
	}
	writeJSON(w, resp)
}

// GET /stats/torrent/<infohash>  (ADMIN-ONLY)
// <infohash> may be hex (40 chars) or percent-encoded 20-byte.
func TorrentStatsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	ihStr := strings.TrimPrefix(r.URL.Path, "/stats/torrent/")
	if ihStr == "" {
		http.Error(w, "missing infohash", http.StatusBadRequest)
		return
	}

	ihBytes, ok := parseIH(ihStr)
	if !ok {
		http.Error(w, "invalid infohash", http.StatusBadRequest)
		return
	}
	var key [20]byte
	copy(key[:], ihBytes)

	// live counts
	liveS, liveL := peerStore.CountsFor(key)

	// DB snapshot (seeders/leechers/completed, flags, times)
	ts, _ := torrentStats.Get(key)

	// determine freeleech mode + expiry
	mode := "off"
	reason := ""
	var expires *time.Time

	// 1) sitewide (settings window if available)
	if flManager.Sitewide() {
		mode = "sitewide"
		reason = "settings"
		if open, _, to, has, err := db.LoadFreeleechWindow(); err == nil && has && open && !to.IsZero() {
			expires = &to
			reason = "settings-window"
		}
	} else {
		// 2) per-torrent flag
		if ts.Frileech {
			mode = "per-torrent"
			reason = "per-flag"
		}

		// 3) 24h window for new/archive (if configured), only if not already per-torrent
		if mode == "off" && config.Freeleech24h && (ts.Section == "new" || ts.Section == "archive") && !ts.Added.IsZero() {
			if time.Since(ts.Added) < 24*time.Hour {
				mode = "24h"
				reason = "24h-window"
				exp := ts.Added.Add(24 * time.Hour)
				expires = &exp
			}
		}

		// 4) “force freeleech for new/archive” switch (displayed as per-torrent)
		if mode == "off" && config.ForceFLNewAndArchive && (ts.Section == "new" || ts.Section == "archive") {
			mode = "per-torrent"
			reason = "section:" + ts.Section
		}
	}

	type out struct {
		Infohash         string  `json:"infohash"`
		LiveSeeders      int     `json:"live_seeders"`
		LiveLeechers     int     `json:"live_leechers"`
		DBSeeders        int     `json:"db_seeders"`
		DBLeechers       int     `json:"db_leechers"`
		DBCompleted      int     `json:"db_completed"`
		FreeleechMode    string  `json:"freeleech_mode"`
		FreeleechReason  string  `json:"freeleech_reason,omitempty"`
		FreeleechExpires *string `json:"freeleech_expires,omitempty"`
		Section          string  `json:"section,omitempty"`
		Added            *string `json:"added,omitempty"`
	}

	res := out{
		Infohash:      hex.EncodeToString(key[:]),
		LiveSeeders:   liveS,
		LiveLeechers:  liveL,
		DBSeeders:     ts.Seeders,
		DBLeechers:    ts.Leechers,
		DBCompleted:   ts.Completed,
		FreeleechMode: mode,
		Section:       ts.Section,
	}
	if reason != "" {
		res.FreeleechReason = reason
	}
	if !ts.Added.IsZero() {
		s := ts.Added.UTC().Format(time.RFC3339)
		res.Added = &s
	}
	if expires != nil {
		s := expires.UTC().Format(time.RFC3339)
		res.FreeleechExpires = &s
	}

	writeJSON(w, res)
}

/* ---------- helpers ---------- */

func parseIH(s string) ([]byte, bool) {
	// hex
	if len(s) == 40 && isHex(s) {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 20 {
			return b, true
		}
	}
	// percent-encoded
	if dec, err := url.QueryUnescape(s); err == nil {
		if len(dec) == 20 {
			return []byte(dec), true
		}
	}
	return nil, false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
