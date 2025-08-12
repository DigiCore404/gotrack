package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	config       *Config
	userCache    *UserCache
	peerStore    *PeerStore
	db           *DB
	startTime    = time.Now()
	torrentStats *TorrentStats // per-torrent seeders/leechers/completed
	ipRules      *IPRules      // dynamic IP bans
)

func startPeerPurger(store *PeerStore, db *DB, cfg *Config) {
	if cfg.PeerTTLSeconds <= 0 || cfg.PeerPurgeIntervalSec <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(cfg.PeerPurgeIntervalSec) * time.Second)
	go func() {
		for range t.C {
			removed := store.PurgeStale(int64(cfg.PeerTTLSeconds), func(p *Peer) {
				if cfg.PurgeDBOnExpire && !cfg.SafeMode {
					_ = db.DeletePeer(p)
				}
			})
			if removed > 0 && cfg.LogVerbose {
				log.Printf("[PURGE] removed %d stale peers (TTL=%ds)", removed, cfg.PeerTTLSeconds)
			}
		}
	}()
}


func main() {
	var err error

	// Load config
	config, err = LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// DB
	db, err = InitDB(config.DB)
	if err != nil {
		log.Fatalf("Failed to connect DB: %v", err)
	}
	log.Println("[DB] Connected")

	// In-memory peer store
	peerStore = NewPeerStore()

	// Warm start peers from DB (best-effort)
	if err := db.LoadPeers(peerStore); err != nil {
		log.Printf("[STARTUP] Warm start peers warning: %v", err)
	}
	tCount, pCount, sCount, lCount := peerStore.Counts()
	log.Printf("[STARTUP] Warm-loaded peers: torrents=%d peers=%d seeders=%d leechers=%d", tCount, pCount, sCount, lCount)

	// Torrent stats cache (from torrents table)
	torrentStats = NewTorrentStats(db)
	if err := torrentStats.Refresh(); err != nil {
		log.Printf("[STARTUP] Torrent stats refresh failed: %v", err)
	} else {
		log.Printf("[STARTUP] Torrent stats loaded: %d torrents with counts", torrentStats.Count())
	}
	go torrentStats.RefreshLoop(5 * time.Minute)

	// User cache (only enabled users)
	userCache = NewUserCache(config.UserCacheTTL, db)
	if err := userCache.Refresh(); err != nil {
		log.Printf("[STARTUP] Initial user cache refresh failed: %v", err)
	} else {
		log.Printf("[STARTUP] Loaded users: %d", userCache.Count())
	}
	go userCache.RefreshLoop()

	// Dynamic IP bans
	ipRules = NewIPRules(db, config)
	if err := ipRules.Refresh(); err != nil {
		log.Printf("[STARTUP] ipban refresh failed: %v", err)
	} else {
		log.Printf("[STARTUP] IP bans loaded: %d dynamic + %d static", ipRules.DynamicCount(), len(config.IPBanlist))
	}
	go ipRules.RefreshLoop(5 * time.Minute)

	// Safe mode toggle
	if config.SafeMode {
		db.SetReadOnly(true)
		log.Println("[SAFE MODE] DB writes are disabled (read-only).")
	} else {
		log.Println("[WRITE MODE] DB writes ENABLED. peers/snatch/users/torrents will be updated on announces.")
	}

	// Start connectable prober (async)
	StartConnectProber(db, peerStore)

// Start stale peer purger (evicts old rows and, optionally, DB)
startPeerPurger(peerStore, db, config)

	// Graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("[SHUTDOWN] Exiting...")
		os.Exit(0)
	}()

	// HTTP routes
	mux := http.NewServeMux()

	// User endpoints
	mux.HandleFunc("/announce", AnnounceHandler)
	mux.HandleFunc("/scrape", ScrapeHandler)

	// Admin endpoints (X-Admin-Key inside handlers)
	mux.HandleFunc("/stats", StatsHandler)
	mux.HandleFunc("/stats/torrent/", TorrentStatsHandler)
	mux.HandleFunc("/peers", PeersListHandler)

	// Legacy path support (/tracker.php/<passkey>/announce|scrape and /announce/<passkey>)
	handler := withLegacy(mux)

       srv := &http.Server{
              Addr:         config.ListenAddr,
              Handler:      handler,
              ReadTimeout:  10 * time.Second,
              WriteTimeout: 10 * time.Second,
              IdleTimeout:  120 * time.Second,
       }

       log.Printf("[HTTP] Listening on %s", config.ListenAddr)
       if err := srv.ListenAndServe(); err != nil { log.Fatal(err) }

}
