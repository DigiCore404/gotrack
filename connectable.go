package main

import (
       "fmt"  
	"log"
	"net"
	"sync"
	"time"
)

const (
	probeWorkers    = 4
	probeTimeout    = 3 * time.Second
	probeCooldown   = 30 * time.Minute // don't re-probe same ip:port too often
	queueSize       = 4096
)

var (
	probeCh      chan *Peer
	probeSeenMu  sync.Mutex
	probeLastRun = make(map[string]time.Time) // key: ip:port
	onceStart    sync.Once
)

func StartConnectProber(db *DB, store *PeerStore) {
	onceStart.Do(func() {
		probeCh = make(chan *Peer, queueSize)
		for i := 0; i < probeWorkers; i++ {
			go probeWorker(db, store)
		}
	})
}

func EnqueueProbe(p *Peer) {
	if p == nil {
		return
	}
	key := p.IP + ":" + itoa(p.Port)
	now := time.Now()
	probeSeenMu.Lock()
	last, ok := probeLastRun[key]
	if ok && now.Sub(last) < probeCooldown {
		probeSeenMu.Unlock()
		return
	}
	probeLastRun[key] = now
	probeSeenMu.Unlock()

	select {
	case probeCh <- p:
	default:
		// queue full; drop silently
	}
}

func probeWorker(db *DB, store *PeerStore) {
    for p := range probeCh {
        addr := net.JoinHostPort(p.IP, itoa(p.Port))
        c, err := net.DialTimeout("tcp", addr, probeTimeout)
        ok := err == nil
        if ok { _ = c.Close() }

        // update memory (the stored copy)
        store.SetConnectable(p.Torrent, p.PeerID, ok)

        if config.SafeMode { continue }

        // try to update; if 0 rows affected, wait briefly and retry once
        if err := db.UpdatePeerConnectable(p, ok); err != nil {
            if config.LogVerbose { log.Printf("[PROBE] update connectable failed for %s: %v", addr, err) }
        }
    }
}

// tiny helpers
func itoa(n int) string { return strconvItoa(n) }

func strconvItoa(n int) string {
	// simple wrapper to avoid importing strconv here; we could import but keeping isolated
	return fmtSprintf("%d", n)
}

func fmtSprintf(format string, a ...any) string {
	return fmt.Sprintf(format, a...)
}
