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

	inf, ok := parseInfoHashLoose(r)
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

	// capture previous snapshot BEFORE we mutate the store
	prev := peerStore.Get(tHash, pID)

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
	// preserve last known connectable status
	if prev != nil {
		peer.Connectable = prev.Connectable
	}

	// In-memory index
	if event == "stopped" {
		peerStore.Remove(tHash, pID)
	} else {
		peer.Frileech = flManager.IsFreeleech(tHash)
		peerStore.AddOrUpdate(peer)
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

	// Stats + snatch updates
	if !config.SafeMode && config.RegisterStats {
		applyStats(r, peer, uploaded, downloaded, seeder, ip, port, r.UserAgent(), event, prev)
	}

	// DB peer write
	if !config.SafeMode {
		if event == "stopped" {
			if err := db.DeletePeer(peer); err != nil {
				log.Printf("[DB] DeletePeer error: %v", err)
			}
			// RECOUNT (exact counts from peers → torrents)
			ihHex := hex.EncodeToString(tHash[:])
			_ = db.RecountTorrentCountsByHash(ihHex)
		} else {
			// UpsertPeer(peer, userID, agent, toGo, seeder, connectable, frileech)
			if err := db.UpsertPeer(
				peer,
				user.ID,
				r.UserAgent(),
				left,
				seeder,
				peer.Connectable, // current flag; prober may update later
				peer.Frileech,    // from flManager
			); err != nil {
				log.Printf("[DB] UpsertPeer failed: %v", err)
			} else {
				// RECOUNT (exact counts from peers → torrents)
				ihHex := hex.EncodeToString(tHash[:])
				_ = db.RecountTorrentCountsByHash(ihHex)
			}
		}
	}

	// enqueue the probe *after* the peer row exists
	if event != "stopped" {
		EnqueueProbe(peer) // async connectable probe
	}

	// --- Uploader first announce handling (ensure snatch + mark finished now) ---
	if !config.SafeMode && prev == nil && seeder {
		tid := 0
		if ts, ok := torrentStats.Get(tHash); ok && ts.ID > 0 {
			tid = ts.ID
		}
		if tid == 0 {
			if meta, err := db.getTorrentMetaByHash(hashHex(tHash)); err == nil && meta.ID > 0 {
				tid = meta.ID
			}
		}
		if tid > 0 {
			_ = db.UpsertSnatch(
				user.ID, tid,
				ip, port, r.UserAgent(),
				peer.Connectable,
				1, 1, 0, 0,
				0, 0,
				true,
			)
			_, _ = db.db.Exec(`UPDATE snatch SET finishedat = NOW() WHERE userid = ? AND torrentid = ?`, user.ID, tid)
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

	var seedDelta int64
	if prev != nil && seeder {
		d := nowUnix() - prev.LastAction
		if d > 0 {
			seedDelta = d
		}
	}

	if config.LogVerbose || config.DebugAnnounce {
		mode := "normal"
		if flManager.Sitewide() {
			mode = "SITEWIDE-FL"
		} else if peer.Frileech {
			mode = "FL"
		}
		log.Printf("[ANNOUNCE] ip=%s uid=%d event=%q seed=%t ih=%s want=%d peers=%d mode=%s complete=%d incomplete=%d downloaded=%d seedtime+=%ds",
			ip, user.ID, event, seeder, hashHex(tHash), numwant, len(plist), mode, s, l, comp, seedDelta)
	}

	// Send bencoded response
	WriteBencode(w, map[string]any{
		"interval":   interval,
		"peers":      compact,
		"complete":   s,
		"incomplete": l,
		"downloaded": comp,
	})
}

func applyStats(
	r *http.Request,
	p *Peer,
	uploaded, downloaded uint64,
	seeder bool,
	ip string,
	port int,
	agent string,
	event string,
	prev *Peer, // snapshot captured BEFORE store mutation
) {
	// 1) Load torrent meta, with DB fallback if cache miss (PHP parity)
	ts, _ := torrentStats.Get(p.Torrent)
	if ts.ID == 0 {
		if meta, err := db.getTorrentMetaByHash(hex.EncodeToString(p.Torrent[:])); err == nil && meta.ID > 0 {
			ts.ID = meta.ID
			ts.Section = meta.Section
			ts.Frileech = meta.Frl
			ts.Added = meta.Added
		}
	}
	if ts.ID == 0 {
		// Still no ID? Nothing to update.
		return
	}

	// 2) User extras
	extra, err := db.GetUserExtra(p.UserID)
	if err != nil {
		return
	}

	// 3) Optional rate-limit logging (same as before)
	skipStats := false
	if config.RateLimitation && prev != nil && prev.LastAction > 0 {
		dt := float64(nowUnix() - prev.LastAction)
		if dt > 0 {
			upDelta := float64(uploaded - prev.Uploaded) / (1024 * 1024) // MB
			upRate := upDelta / dt                                        // MB/s
			if upRate >= float64(config.RateWarnUpMBps) && config.RateWarnUpMBps > 0 {
				log.Printf("[RATE-WARN] uid=%d ip=%s up=%.2f MB/s ih=%s", p.UserID, ip, upRate, hashHex(p.Torrent))
			}
			if upRate >= float64(config.RateErrUpMBps) && config.RateErrUpMBps > 0 {
				log.Printf("[RATE-ERR] uid=%d ip=%s up=%.2f MB/s ih=%s -> dropping stats write", p.UserID, ip, upRate, hashHex(p.Torrent))
				skipStats = true
			}
		}
	}
	if skipStats {
		return
	}

	// 4) Deltas (real + counted). PHP only counts deltas when we have a prev.
	var addUpReal, addDownReal uint64
	var addUpCounted, addDownCounted uint64
	if prev != nil && uploaded > prev.Uploaded {
		addUpReal = uploaded - prev.Uploaded
		addUpCounted = addUpReal * uint64(config.UploadMultiplier)
	}
	if prev != nil && downloaded > prev.Downloaded {
		addDownReal = downloaded - prev.Downloaded
		addDownCounted = addDownReal * uint64(config.DownloadMultiplier)
	}

	// 5) Section split for seed upload
	var nyttSeed, arkivSeed uint64
	if ts.Section == "new" {
		nyttSeed = addUpCounted
	} else {
		arkivSeed = addUpCounted
	}

	// 6) FREELEECH rules: sitewide/per-torrent/24h + force for new/archive (matches your PHP)
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
		// Counted DL is zero, but we still store REAL DL in snatch (PHP uses add_down2 there)
		addDownCounted = 0
	} else {
		procent := float64(100-extra.LeechBonus) / 100.0
		if procent < 0 {
			procent = 0
		}
		addDownCounted = uint64(float64(addDownCounted) * procent)
	}

	// 7) Hidden IP for high class
	dip := ip
	if extra.Class >= 50 {
		dip = "Hidden IP"
	}

	// 8) Users table (only when we have real deltas)
	if (addUpReal | addDownReal) > 0 {
		_ = db.UpdateUserStats(
			p.UserID,
			addUpCounted,  // uploaded (counted)
			addUpReal,     // uploaded_real
			addDownCounted, // downloaded (counted; may be 0 due to FL)
			addDownReal,    // downloaded_real
			nyttSeed, arkivSeed,
			dip,
		)
	}

	// 9) HnR clear if seeding
	if seeder {
		db.ClearHnRIfSeeding(p.UserID, ts.ID)
	}

	// 10) Counters like PHP
	timesStarted, timesCompleted, timesUpdated, timesStopped := 0, 0, 0, 0
	switch event {
	case "started":
		timesStarted = 1
	case "completed":
		if r.URL.Query().Get("left") == "0" {
			timesCompleted = 1
		} else {
			timesUpdated = 1
		}
	case "stopped":
		if r.URL.Query().Get("left") != "0" {
			timesStopped = 1
		}
	default:
		timesUpdated = 1
	}

	// 11) Completed bump (seeders++, leechers--, times_completed++)
	if timesCompleted == 1 {
		_ = db.OnCompleted(ts.ID, p.UserID)
	}

	// 12) Upsert snatch: store REAL deltas in snatch.uploaded/downloaded (PHP parity)
	_ = db.UpsertSnatch(
		p.UserID, ts.ID,
		ip, port, agent,
		p.Connectable,
		timesStarted, timesCompleted, timesUpdated, timesStopped,
		addUpReal, addDownReal, // REAL deltas go to snatch
		seeder,
	)
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


// parseInfoHashLoose replicates PHP-style tolerance:
//
// 1) Try the strict parser you had (percent-decoded/hex -> 20 bytes).
// 2) If that fails, extract the raw value from RawQuery so '+' isn't turned into space,
//    replace '+' with "%2B", unescape once, and accept if it yields 20 bytes.
// 3) If still not 20, accept a 40-hex string (case-insensitive) and decode to 20 bytes.
func parseInfoHashLoose(r *http.Request) ([]byte, bool) {
	// 1) your existing strict path
	if b, ok := parse20(r.URL.Query().Get("info_hash")); ok {
		return b, true
	}

	raw := r.URL.RawQuery
	if raw == "" {
		return nil, false
	}

	// 2) pull the exact info_hash value from RawQuery to avoid '+' => ' ' conversion
	var enc string
	for i := 0; i < len(raw); {
		j := strings.IndexByte(raw[i:], '&')
		item := raw[i:]
		if j >= 0 {
			item = raw[i : i+j]
		}
		if strings.HasPrefix(item, "info_hash=") {
			enc = item[len("info_hash="):]
			break
		}
		if j < 0 {
			break
		}
		i += j + 1
	}
	if enc == "" {
		return nil, false
	}

	// Treat literal '+' as "%2B" before unescape (PHP would not auto-space it for this field)
	enc = strings.ReplaceAll(enc, "+", "%2B")

	// Try single unescape
	if dec, err := url.QueryUnescape(enc); err == nil {
		if len(dec) == 20 {
			return []byte(dec), true
		}
		// Also allow 40-char hex after one decode (some old torrents stored as hex)
		if len(dec) == 40 && isHex(dec) {
			if b, err := hex.DecodeString(dec); err == nil && len(b) == 20 {
				return b, true
			}
		}
	}

	// Final fallback: if the raw value itself looks like hex
	if len(enc) == 40 && isHex(enc) {
		if b, err := hex.DecodeString(enc); err == nil && len(b) == 20 {
			return b, true
		}
	}
	return nil, false
}
