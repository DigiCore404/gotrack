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
	"fmt"
	"bytes"
)


// maskPasskey shows head+tail and hides the middle
func maskPasskey(pk string) string {
	if pk == "" {
		return ""
	}
	if len(pk) <= 10 {
		return "****"
	}
	return pk[:6] + "…" + pk[len(pk)-4:]
}

var announceCount uint64

func AnnounceHandler(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&announceCount, 1)

	if config.DebugAnnounce {
    		log.Printf("[ANNOUNCE INFO] ip=%s ua=%q path=%s qs=%q",
        	getRealIP(r), r.UserAgent(), r.URL.Path, r.URL.RawQuery)
	}

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


	if !ipRules.IsAllowed(ip) {
    		if config.DebugAnnounce {
        		log.Printf("[ANNOUNCE REJECT] banned IP ip=%s qs=%q", ip, r.URL.RawQuery)
    		}
    		BencodeError(w, "Banned IP"); return
	}

	passkey := r.URL.Query().Get("passkey")
	if len(passkey) != 32 {
		BencodeError(w, "Invalid passkey")
		return
	}

	// after reading passkey:
	if len(passkey) != 32 {
    		if config.DebugAnnounce {
        		log.Printf("[ANNOUNCE REJECT] invalid passkey qs=%q", r.URL.RawQuery)
    		}
    		BencodeError(w, "Invalid passkey"); return
	}

	user, ok := userCache.GetOrFetch(passkey)

	if !ok {
    		if config.DebugAnnounce {
        		log.Printf("[ANNOUNCE REJECT] unknown passkey ip=%s qs=%q", ip, r.URL.RawQuery)
    		}
    		BencodeError(w, "Unknown passkey"); return
	}


	if !user.Enabled {
		BencodeError(w, "Account disabled")
		return
	}

	// after parseInfoHashLoose:
	inf, ok := parseInfoHashLoose(r)

		if !ok {
    			if config.DebugAnnounce {
        			log.Printf("[ANNOUNCE REJECT] invalid info_hash ip=%s qs=%q", ip, r.URL.RawQuery)
    			}
    		BencodeError(w, "Invalid info hash"); return
	}

	pid, ok := parse20(r.URL.Query().Get("peer_id"))

	if !ok {
		BencodeError(w, "Invalid peer id")
		return
	}

	if config.DebugAnnounce {
		log.Printf("[ANNOUNCE INFO] ip=%s passkey=%s rawQS=%q",
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

	seeder := left == 0 || event == "completed"

	var tHash, pID [20]byte
	copy(tHash[:], inf)
	copy(pID[:], pid)


	// ===== DEBUG: prove announce hit for this torrent + params =====
	if config.DebugAnnounce {
		ihHex := hashHex(tHash)
		log.Printf("[ANNOUNCE INFO] ih=%s uid=%d left=%d event=%q ip=%s:%d up=%d down=%d seeder=%t",
			ihHex, user.ID, left, event, ip, port, uploaded, downloaded, seeder)
	}


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


// ---- Allow seeding/stopped for download-banned users, block leeching ----
if user.DownloadBan {
    // allow announces that are clearly not downloading:
    // - seeding (left==0)
    // - stopping (event == "stopped") so we can clean up
    if seeder || event == "stopped" {
        if config.DebugAnnounce {
            log.Printf("[ANNOUNCE INFO] uid=%d is download-banned but allowed (seeder=%t event=%q)", user.ID, seeder, event)
        }
        // proceed
    } else {
        if config.DebugAnnounce {
            log.Printf("[ANNOUNCE REJECT] uid=%d download-banned and attempting to leech (left=%d event=%q) ip=%s qs=%q",
                user.ID, left, event, ip, r.URL.RawQuery)
        }
        BencodeError(w, "Download banned — you may seed only to clear HnR.")
        return
    }
}

	interval := rand.Intn(config.AnnounceIntervalMax-config.AnnounceIntervalMin+1) + config.AnnounceIntervalMin

	// Stats + snatch updates
	if !config.SafeMode && config.RegisterStats {
		applyStats(r, peer, uploaded, downloaded, seeder, ip, port, r.UserAgent(), event, prev)
	}


// DB peer write (sync)
if !config.SafeMode {
    ihHex := hex.EncodeToString(tHash[:])
    if event == "stopped" {
        if err := db.DeletePeer(peer); err != nil {
            log.Printf("[DB] DeletePeer error: %v", err)
        }
        _ = db.RecountTorrentCountsByHash(ihHex)
    } else {
        if err := db.UpsertPeer(
            peer,
            user.ID,
            r.UserAgent(),
            left,
            seeder,
            peer.Connectable,
            peer.Frileech,
            event,
        ); err != nil {
            log.Printf("[DB] UpsertPeer error: %v ih=%s ip=%s port=%d uid=%d",
                err, ihHex, peer.IP, peer.Port, user.ID)
        } else {
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

	if config.DebugAnnounce {
		mode := "normal"
		if flManager.Sitewide() {
			mode = "SITEWIDE-FL"
		} else if peer.Frileech {
			mode = "FL"
		}
		log.Printf("[ANNOUNCE INFO] ip=%s uid=%d event=%q seed=%t ih=%s want=%d peers=%d mode=%s complete=%d incomplete=%d downloaded=%d seedtime+=%ds",
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
	// 1) Load torrent meta, with DB fallback (PHP parity)
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
		return
	}

	// 2) User extras
	extra, err := db.GetUserExtra(p.UserID)
	if err != nil {
		return
	}

	// 3) Optional rate-limit logging
	skipStats := false
	if config.RateLimitation && prev != nil && prev.LastAction > 0 {
		dt := float64(nowUnix() - prev.LastAction)
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
	if skipStats {
		return
	}

	// 4) Deltas (real + counted) — only when we have a prev snapshot
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

	// 6) FREELEECH rules
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

	// 10) Counters — treat first sight as a "started" even when event is empty
	timesStarted, timesCompleted, timesUpdated, timesStopped := 0, 0, 0, 0
	if prev == nil {
		timesStarted = 1
	}
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

	// 11) Completed bump
	if timesCompleted == 1 {
		_ = db.OnCompleted(ts.ID, p.UserID)
	}

	// 12) Upsert snatch: store REAL deltas in snatch
	_ = db.UpsertSnatch(
		p.UserID, ts.ID,
		ip, port, agent,
		p.Connectable,
		timesStarted, timesCompleted, timesUpdated, timesStopped,
		addUpReal, addDownReal,
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


// Percent-decoder that treats '+' as space (standard form encoding)
func unescapeInfoHashPlusIsSpace(s string) ([]byte, error) {
	out := make([]byte, 0, 20)
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("short escape")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, err
			}
			out = append(out, byte(v))
			i += 3
		case '+':
			// standard form encoding: '+' means space (0x20)
			out = append(out, ' ')
			i++
		default:
			out = append(out, s[i])
			i++
		}
	}
	return out, nil
}

// Percent-decoder that PRESERVES '+' as literal 0x2B (fallback)
func unescapeInfoHashPreservePlus(s string) ([]byte, error) {
	out := make([]byte, 0, 20)
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("short escape")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, err
			}
			out = append(out, byte(v))
			i += 3
		default:
			out = append(out, s[i])
			i++
		}
	}
	return out, nil
}

// parseInfoHashLoose decodes info_hash from RawQuery without losing '+'
// Strategy:
//  1) Extract raw token after "info_hash=" from RawQuery.
//  2) Decode with '+' preserved as 0x2B (correct for URLs).
//  3) Also decode with '+' treated as space (form-style fallback).
//  4) If both are 20 bytes and differ, consult DB: pick the one that exists.
//  5) Else fall back to any valid 20-byte candidate.
//  6) Finally, try 40-char hex param as last resort.
func parseInfoHashLoose(r *http.Request) ([]byte, bool) {
	raw := r.URL.RawQuery

	// Try percent-encoded binary from RawQuery
	if i := strings.Index(raw, "info_hash="); i >= 0 {
		v := raw[i+len("info_hash="):]
		if j := strings.IndexByte(v, '&'); j >= 0 {
			v = v[:j]
		}

		// Variant A: PRESERVE '+' as 0x2B (URL semantics)
		varA, errA := unescapeInfoHashPreservePlus(v)
		okA := (errA == nil && len(varA) == 20)

		// Variant B: Treat '+' as SPACE 0x20 (form-encoding fallback)
		varB, errB := unescapeInfoHashPlusIsSpace(v)
		okB := (errB == nil && len(varB) == 20)

		switch {
		case okA && okB:
			// If they differ, choose the one that exists in DB
			if !bytes.Equal(varA, varB) {
				hexA := hex.EncodeToString(varA)
				hexB := hex.EncodeToString(varB)

				// use the existing meta lookup helper; pick whichever exists
				if metaA, err := db.getTorrentMetaByHash(hexA); err == nil && metaA.ID > 0 {
					if config.DebugAnnounce {
						log.Printf("[ANNOUNCE INFO] ih disambiguation chose PRESERVE-PLUS (ih=%s)", hexA)
					}
					return varA, true
				}
				if metaB, err := db.getTorrentMetaByHash(hexB); err == nil && metaB.ID > 0 {
					if config.DebugAnnounce {
						log.Printf("[ANNOUNCE INFO] ih disambiguation chose PLUS-AS-SPACE (ih=%s)", hexB)
					}
					return varB, true
				}

				// Neither found: prefer PRESERVE-PLUS (safer for URLs)
				if config.DebugAnnounce {
					log.Printf("[ANNOUNCE INFO] ih disambiguation: no DB match; defaulting to PRESERVE-PLUS (ih=%s)", hexA)
				}
				return varA, true
			}
			// Same bytes either way
			return varA, true

		case okA:
			return varA, true
		case okB:
			return varB, true
		}
	}

	// 40-char hex fallback
	s := r.URL.Query().Get("info_hash")
	if len(s) == 40 && isHex(s) {
		dst := make([]byte, 20)
		if _, err := hex.Decode(dst, []byte(s)); err == nil {
			return dst, true
		}
	}
	return nil, false
}
