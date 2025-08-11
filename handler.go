package main

import (
	"encoding/hex"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var announceCount uint64

func AnnounceHandler(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&announceCount, 1)

	// Do NOT reject "old protocol" flags (Deluge may send no_peer_id=1)
	if IsUserAgentBanned(r.UserAgent()) {
		BencodeError(w, "Banned client")
		return
	}
	ip := getRealIP(r)
	if !ipRules.IsAllowed(ip) {
		BencodeError(w, "Banned IP")
		return
	}

	passkey := r.URL.Query().Get("passkey")
	if len(passkey) != 32 {
		BencodeError(w, "Invalid passkey")
		return
	}
	user, ok := userCache.GetOrFetch(passkey)
	if !ok {
		BencodeError(w, "Unknown passkey")
		return
	}
	if !user.Enabled {
		BencodeError(w, "Account disabled")
		return
	}
	if user.DownloadBan {
		BencodeError(w, "Download banned")
		return
	}

	inf, ok := parse20(r.URL.Query().Get("info_hash"))
	if !ok {
		BencodeError(w, "Invalid info hash")
		return
	}
	pid, ok := parse20(r.URL.Query().Get("peer_id"))
	if !ok {
		BencodeError(w, "Invalid peer id")
		return
	}

	if config.DebugAnnounce {
		log.Printf("[ANNOUNCE DEBUG] ip=%s passkey=%s rawQS=%q",
			getRealIP(r), passkey, r.URL.RawQuery)
	}

	port, _ := atoiSafe(r.URL.Query().Get("port"))
	if port < 1 || port > 65535 {
		BencodeError(w, "Invalid port")
		return
	}
	uploaded := u64Safe(r.URL.Query().Get("uploaded"))
	downloaded := u64Safe(r.URL.Query().Get("downloaded"))
	left := u64Safe(r.URL.Query().Get("left"))
	event := r.URL.Query().Get("event")
	numwant := clampNumwant(r.URL.Query().Get("numwant"))

	seeder := left == 0

	var tHash, pID [20]byte
	copy(tHash[:], inf)
	copy(pID[:], pid)

	peer := &Peer{
		Torrent:    tHash,
		UserID:     user.ID,
		PeerID:     pID,
		IP:         ip,
		Port:       port,
		Uploaded:   uploaded,
		Downloaded: downloaded,
		Seeder:     seeder,
		LastAction: nowUnix(),
	}

	// In-memory index
	if event == "stopped" {
		peerStore.Remove(tHash, pID)
	} else {
		peer.Frileech = flManager.IsFreeleech(tHash)
		peerStore.AddOrUpdate(peer)
		EnqueueProbe(peer) // async connectable probe
	}

	// Response peers (compact)
	plist := peerStore.SelectPeers(tHash, numwant, seeder)
	var compact []byte
	for _, p := range plist {
		if b := CompactPeer(p); b != nil {
			compact = append(compact, b...)
		}
	}

	interval := rand.Intn(config.AnnounceIntervalMax-config.AnnounceIntervalMin+1) + config.AnnounceIntervalMin

	// Writes
	if !config.SafeMode && config.RegisterStats && event != "stopped" {
		applyStats(r, peer, uploaded, downloaded, seeder, ip)
	}
	if !config.SafeMode {
		if event == "stopped" {
			if err := db.DeletePeer(peer); err != nil {
				log.Printf("[DB] DeletePeer error: %v", err)
			}
		} else {
			if err := db.UpsertPeer(peer, user.ID, r.UserAgent(), left, seeder, true, flManager.IsFreeleech(tHash)); err != nil {
				log.Printf("[DB] UpsertPeer failed: %v", err)
			}
		}
	}

	// Counts for clients (seeders/leechers/completed)
	s, l := peerStore.CountsFor(tHash)
	if s == 0 && l == 0 {
		if ts, ok := torrentStats.Get(tHash); ok {
			s, l = ts.Seeders, ts.Leechers
		}
	}
	comp := 0
	if ts, ok := torrentStats.Get(tHash); ok {
		comp = ts.Completed
	}

	if config.LogVerbose {
		mode := "normal"
		if flManager.Sitewide() {
			mode = "SITEWIDE-FL"
		} else if peer.Frileech {
			mode = "FL"
		}
		log.Printf("[ANNOUNCE] ip=%s uid=%d event=%q seed=%t ih=%s want=%d peers=%d mode=%s",
			ip, user.ID, event, seeder, hashHex(tHash), numwant, len(plist), mode)
	}

	// Send bencoded response
	WriteBencode(w, map[string]any{
		"interval":   interval,
		"peers":      compact,
		"complete":   s,    // seeders
		"incomplete": l,    // leechers
		"downloaded": comp, // completed
	})
}

func applyStats(r *http.Request, p *Peer, uploaded, downloaded uint64, seeder bool, ip string) {
	ts, _ := torrentStats.Get(p.Torrent)
	extra, err := db.GetUserExtra(p.UserID)
	if err != nil {
		return
	}

	// rate-limit check
	skipStats := false
	if config.RateLimitation {
		prevPeers := peerStore.GetPeers(p.Torrent, false)
		var prev *Peer
		for _, cand := range prevPeers {
			if cand.PeerID == p.PeerID {
				prev = cand
				break
			}
		}
		if prev != nil && prev.LastAction > 0 {
			dt := float64(nowUnix()-prev.LastAction)
			if dt > 0 {
				upDelta := float64(uploaded - prev.Uploaded) / (1024 * 1024)
				upRate := upDelta / dt
				if upRate >= float64(config.RateWarnUpMBps) && config.RateWarnUpMBps > 0 {
					log.Printf("[RATE-WARN] uid=%d ip=%s up=%.2f MB/s ih=%s", p.UserID, ip, upRate, hashHex(p.Torrent))
				}
				if upRate >= float64(config.RateErrUpMBps) && config.RateErrUpMBps > 0 {
					log.Printf("[RATE-ERR] uid=%d ip=%s up=%.2f MB/s ih=%s -> dropping stats write", p.UserID, ip, upRate, hashHex(p.Torrent))
					skipStats = true
				}
			}
		}
	}
	if skipStats {
		return
	}

	// deltas
	var addUpReal, addDownReal uint64
	var addUpCounted, addDownCounted uint64
	if uploaded > p.Uploaded {
		addUpReal = uploaded - p.Uploaded
		addUpCounted = addUpReal * uint64(config.UploadMultiplier)
	}
	if downloaded > p.Downloaded {
		addDownReal = downloaded - p.Downloaded
		addDownCounted = addDownReal * uint64(config.DownloadMultiplier)
	}

	// split seed upload across sections
	var nyttSeed, arkivSeed uint64
	if ts.Section == "new" {
		nyttSeed = addUpCounted
	} else {
		arkivSeed = addUpCounted
	}

	// FREELEECH rules
	isFL := false
	if config.ForceFLNewAndArchive && (ts.Section == "new" || ts.Section == "archive") {
		isFL = true
	}
	if !isFL && !ts.Frileech && (ts.Section == "new" || ts.Section == "archive") && !ts.Added.IsZero() && time.Since(ts.Added) < 24*time.Hour && config.Freeleech24h {
		isFL = true
	}
	if !isFL && ts.Frileech {
		isFL = true
	}
	if flManager.Sitewide() {
		isFL = true
	}
	if isFL {
		addDownCounted = 0
	} else {
		procent := float64(100-extra.LeechBonus) / 100.0
		if procent < 0 {
			procent = 0
		}
		addDownCounted = uint64(float64(addDownCounted) * procent)
	}

	// hidden IP for high class
	dip := ip
	if extra.Class >= 50 {
		dip = "Hidden IP"
	}

	// write user stats if any delta
	if (addUpReal|addDownReal) > 0 {
		_ = db.UpdateUserStats(p.UserID, addUpCounted, addUpReal, addDownCounted, addDownReal, nyttSeed, arkivSeed, dip)
	}

	// With ID in cache, do precise torrent/snatch updates
	torrentID := ts.ID
	if torrentID > 0 {
		// HnR clear while seeding
		if seeder {
			db.ClearHnRIfSeeding(p.UserID, torrentID)
		}
		// counters
		var c, s, u int
		if r.URL.Query().Get("event") == "completed" && r.URL.Query().Get("left") == "0" {
			c = 1
		} else if r.URL.Query().Get("event") == "stopped" && r.URL.Query().Get("left") != "0" {
			s = 1
		} else {
			u = 1
		}
		db.BumpSnatchCounters(p.UserID, torrentID, c, s, u)

		// completed → bump torrents + finishedat
		if c == 1 {
			_ = db.OnCompleted(torrentID, p.UserID)
		}
	}
}

func clampNumwant(s string) int {
	want := config.DefaultGivePeers
	if s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			want = n
		}
	}
	if want > config.MaxGivePeers {
		want = config.MaxGivePeers
	}
	if want < 0 {
		want = 0
	}
	return want
}

/* ---------- SCRAPE ---------- */

func ScrapeHandler(w http.ResponseWriter, r *http.Request) {
	if !config.AllowGlobalScrape {
		if len(r.URL.Query()["info_hash"]) == 0 {
			BencodeError(w, "Global scrape disabled")
			return
		}
	}
	if IsUserAgentBanned(r.UserAgent()) {
		BencodeError(w, "Banned client")
		return
	}
	ip := getRealIP(r)
	if !ipRules.IsAllowed(ip) {
		BencodeError(w, "Banned IP")
		return
	}

	passkey := r.URL.Query().Get("passkey")
	if len(passkey) != 32 {
		BencodeError(w, "Invalid passkey")
		return
	}
	user, ok := userCache.GetOrFetch(passkey)
	if !ok || !user.Enabled || user.DownloadBan {
		BencodeError(w, "Unauthorized")
		return
	}

	raw := r.URL.Query()["info_hash"]
	if !config.AllowGlobalScrape && len(raw) == 0 {
		BencodeError(w, "Missing info_hash")
		return
	}
	if len(raw) == 0 && config.AllowGlobalScrape {
		WriteBencode(w, map[string]any{"files": map[string]any{}})
		return
	}

	type stats struct {
		Complete   int `bencode:"complete"`
		Downloaded int `bencode:"downloaded"`
		Incomplete int `bencode:"incomplete"`
	}

	files := make(map[string]stats, len(raw))
	for _, ihStr := range raw {
		ihBytes, ok := parse20Scrape(ihStr)
		if !ok {
			continue
		}
		var key [20]byte
		copy(key[:], ihBytes)

		s, l := peerStore.CountsFor(key)
		if s == 0 && l == 0 {
			if ts, ok := torrentStats.Get(key); ok {
				s, l = ts.Seeders, ts.Leechers
			}
		}
		comp := 0
		if ts, ok := torrentStats.Get(key); ok {
			comp = ts.Completed
		}

		files[string(ihBytes)] = stats{
			Complete:   s,
			Downloaded: comp,
			Incomplete: l,
		}
	}
	WriteBencode(w, map[string]any{"files": files})
}

/* ---------- helpers ---------- */

func getRealIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	hostPart := r.RemoteAddr
	if i := strings.LastIndex(hostPart, ":"); i > 0 {
		return hostPart[:i]
	}
	return hostPart
}

func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func u64Safe(s string) uint64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func parse20(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	if len(s) == 40 && isHex(s) {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 20 {
			return nil, false
		}
		return b, true
	}
	dec, err := url.QueryUnescape(s)
	if err != nil {
		return nil, false
	}
	b := []byte(dec)
	if len(b) != 20 {
		return nil, false
	}
	return b, true
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func parse20Scrape(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	if dec, err := url.QueryUnescape(s); err == nil {
		b := []byte(dec)
		if len(b) == 20 {
			return b, true
		}
	}
	if len(s) == 40 && isHex(s) {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 20 {
			return b, true
		}
	}
	return nil, false
}

func hashHex(h [20]byte) string { return hex.EncodeToString(h[:]) }