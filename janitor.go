package main

import (
	"log"
	"time"
)

// startJanitor runs an in-memory peer expiry loop.
//
// Behavior:
// - If config.PeerFlushInterval > 0  => DISABLE janitor (assume DB-side cleanup owns expiry)
// - Else                             => ENABLE janitor:
//      * every PeerPurgeIntervalSec, remove peers idle > PeerTTLSeconds from memory
//      * if PurgeDBOnExpire && !SafeMode, also delete those peers from the DB
//
// Uses peerStore.Snapshot() + targeted Remove() to avoid doing DB calls under store locks.
func startJanitor() {
	// If we’re periodically flushing to DB, let DB-side cleanup own expiry
	if config.PeerFlushInterval > 0 {
		log.Printf("[JANITOR] Disabled (peer_flush_interval=%d > 0; DB cleanup owns expiry)", config.PeerFlushInterval)
		return
	}

	ttl := config.PeerTTLSeconds
	interval := config.PeerPurgeIntervalSec
	if ttl <= 0 {
		ttl = 900 // sane default 15m
	}
	if interval <= 0 {
		interval = 60 // sane default 60s
	}

	log.Printf("[JANITOR] Enabled: every %ds, ttl=%ds, purge_db=%v",
		interval, ttl, config.PurgeDBOnExpire)

	go func() {
		t := time.NewTicker(time.Duration(interval) * time.Second)
		defer t.Stop()

		for range t.C {
			now := time.Now().Unix()
			staleCutoff := now - int64(ttl)

			// Snapshot to avoid holding locks during DB IO
			all := peerStore.Snapshot()
			var removed int

			for _, p := range all {
				if p == nil || p.LastAction > staleCutoff {
					continue
				}
				// remove from memory
				peerStore.Remove(p.Torrent, p.PeerID)
				removed++

				// optionally remove from DB as well (only if not in safe mode)
				if config.PurgeDBOnExpire && !config.SafeMode {
					_ = db.DeletePeer(p)
				}
			}

			if removed > 0 && config.LogVerbose {
				log.Printf("[JANITOR] Purged %d stale peers from memory", removed)
			}
		}
	}()
}