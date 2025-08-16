package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/* ---------- /stats (ADMIN) ---------- */

func StatsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	// Base counts from the in-memory peer store
	torrentsLive, peersLive, seedersLive, leechersLive := peerStore.Counts()

	// Build richer aggregates from a snapshot (no locks held during work)
	snap := peerStore.Snapshot()
	now := time.Now().Unix()

	// Per-torrent live swarm map
	type swarmAgg struct{ seeders, leechers int }
	perTorrent := make(map[[20]byte]*swarmAgg, torrentsLive)

	// Totals from live peers (note: these are *current session* counters, not DB-aggregated stats)
	var totalUploaded uint64
	var totalDownloaded uint64
	var activePeers15m int

	for _, p := range snap {
		if p == nil {
			continue
		}
		totalUploaded += p.Uploaded
		totalDownloaded += p.Downloaded
		if now-p.LastAction <= 15*60 {
			activePeers15m++
		}
		agg := perTorrent[p.Torrent]
		if agg == nil {
			agg = &swarmAgg{}
			perTorrent[p.Torrent] = agg
		}
		if p.Seeder {
			agg.seeders++
		} else {
			agg.leechers++
		}
	}

	// Swarm health derived from per-torrent aggregates
	unseededTorrents := 0
	singleSeederTorrents := 0
	freeleechTorrents := 0
	completedTotal := 0

	for ih, agg := range perTorrent {
		if agg.seeders == 0 {
			unseededTorrents++
		} else if agg.seeders == 1 {
			singleSeederTorrents++
		}

		// Look up cached DB snapshot for flags/counters
		if ts, ok := torrentStats.Get(ih); ok {
			// Count freeleech by effective rules (sitewide handled separately in summary)
			isFL := ts.Frileech
			if !isFL && config.ForceFLNewAndArchive && (ts.Section == "new" || ts.Section == "archive") {
				isFL = true
			}
			if !isFL && config.Freeleech24h && (ts.Section == "new" || ts.Section == "archive") && !ts.Added.IsZero() && time.Since(ts.Added) < 24*time.Hour {
				isFL = true
			}
			if isFL {
				freeleechTorrents++
			}
			completedTotal += ts.Completed
		}
	}

	// Ratios
	var seederRatio float64
	if seedersLive+leechersLive > 0 {
		seederRatio = float64(seedersLive) / float64(seedersLive+leechersLive)
	}

	type summary struct {
		// Existing fields
		UptimeSeconds   int64  `json:"uptime_seconds"`
		StartedAt       string `json:"started_at"`
		Torrents        int    `json:"torrents"`
		Peers           int    `json:"peers"`
		Seeders         int    `json:"seeders"`
		Leechers        int    `json:"leechers"`
		SafeMode        bool   `json:"safe_mode"`
		SitewideFL      bool   `json:"sitewide_freeleech"`

		// New fields
		UptimeHuman            string  `json:"uptime_human"`
		SeederRatio            float64 `json:"seeder_ratio"`
		ActivePeers15m         int     `json:"active_peers_15m"`
		UploadedTotal          uint64  `json:"uploaded_total"`
		DownloadedTotal        uint64  `json:"downloaded_total"`
		UnseededTorrents       int     `json:"unseeded_torrents"`
		SingleSeederTorrents   int     `json:"single_seeder_torrents"`
		FreeleechTorrentsLive  int     `json:"freeleech_torrents_live"`
		CompletedTotalLiveView int     `json:"completed_total_live_view"`
	}

	uptime := time.Since(startTime)
	resp := summary{
		// existing
		UptimeSeconds: time.Since(startTime).Round(time.Second).Milliseconds() / 1000,
		StartedAt:     startTime.UTC().Format(time.RFC3339),
		Torrents:      torrentsLive,
		Peers:         peersLive,
		Seeders:       seedersLive,
		Leechers:      leechersLive,
		SafeMode:      config.SafeMode,
		SitewideFL:    flManager.Sitewide(),

		// new
		UptimeHuman:            humanUptime(uptime),
		SeederRatio:            seederRatio,
		ActivePeers15m:         activePeers15m,
		UploadedTotal:          totalUploaded,
		DownloadedTotal:        totalDownloaded,
		UnseededTorrents:       unseededTorrents,
		SingleSeederTorrents:   singleSeederTorrents,
		FreeleechTorrentsLive:  freeleechTorrents,
		CompletedTotalLiveView: completedTotal,
	}

	writeJSON(w, resp)
}

func humanUptime(d time.Duration) string {
	// produce a compact human string, e.g. "2d 4h 17m"
	sec := int64(d.Seconds())
	if sec < 60 {
		return "0m"
	}
	min := sec / 60
	h := min / 60
	days := h / 24
	min = min % 60
	h = h % 24
	switch {
	case days > 0:
		return plural(days, "d") + " " + plural(h, "h") + " " + plural(min, "m")
	case h > 0:
		return plural(h, "h") + " " + plural(min, "m")
	default:
		return plural(min, "m")
	}
}

func plural(n int64, suffix string) string {
	return strconvFormat(n) + suffix
}

func strconvFormat(n int64) string {
	// tiny helper to avoid extra import for fmt
	buf := [20]byte{}
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	if n == 0 {
		return "0"
	}
	for n > 0 && i > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg && i > 0 {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

/* ---------- /stats/torrent/<infohash> (ADMIN) ---------- */

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
