package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr        string   `yaml:"listen_addr"`
	DB                DBConfig `yaml:"db"`

	PeerFlushInterval int      `yaml:"peer_flush_interval"` // seconds; >0 enables periodic writes when not in safe_mode
	UserCacheTTL      int      `yaml:"user_cache_ttl"`
	IPWhitelist       []string `yaml:"ip_whitelist"`
	IPBanlist         []string `yaml:"ip_banlist"`
	UserAgentBan      []string `yaml:"user_agent_ban"`

	SafeMode     bool `yaml:"safe_mode"`
	LogVerbose   bool `yaml:"log_verbose"`
	DebugAnnounce bool `yaml:"debug_announce"`

	AdminAPIKey string `yaml:"admin_api_key"`

	// Freeleech controls
	SitewideFreeleech bool `yaml:"sitewide_freeleech"`
	Freeleech24h      bool `yaml:"freeleech_24h"`
	DBFreeleechWatch  bool `yaml:"db_freeleech_watch"`
	ForceFLNewAndArchive bool `yaml:"force_fl_new_archive"`

	// PHP-parity tracker settings
	Gzip                 bool `yaml:"gzip"`
	AllowOldProtocols    bool `yaml:"allow_old_protocols"`
	AllowGlobalScrape    bool `yaml:"allow_global_scrape"`
	DefaultGivePeers     int  `yaml:"default_give_peers"`
	MaxGivePeers         int  `yaml:"max_give_peers"`
	RateLimitation       bool `yaml:"rate_limitation"`
	RateWarnUpMBps       int  `yaml:"rate_limitation_warn_up"` // MB/s
	RateErrUpMBps        int  `yaml:"rate_limitation_err_up"`  // MB/s
	RegisterStats        bool `yaml:"register_stats"`
	UploadMultiplier     int  `yaml:"upload_multiplier"`
	DownloadMultiplier   int  `yaml:"download_multiplier"`
	AnnounceIntervalMin  int  `yaml:"announce_interval_min"` // seconds
	AnnounceIntervalMax  int  `yaml:"announce_interval_max"` // seconds

	// Cleanup knobs
	PeerTTLSeconds       int  `yaml:"peer_ttl_seconds"`        // e.g. 3600
	PeerPurgeIntervalSec int  `yaml:"peer_purge_interval_sec"` // e.g. 300
	PurgeDBOnExpire      bool `yaml:"purge_db_on_expire"`
}

type DBConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	User string `yaml:"user"`
	Pass string `yaml:"pass"`
	Name string `yaml:"name"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	// sane defaults
	if cfg.DefaultGivePeers == 0 {
		cfg.DefaultGivePeers = 50
	}
	if cfg.MaxGivePeers == 0 {
		cfg.MaxGivePeers = 150
	}
	if cfg.AnnounceIntervalMin == 0 {
		cfg.AnnounceIntervalMin = 1800
	}
	if cfg.AnnounceIntervalMax == 0 {
		cfg.AnnounceIntervalMax = 2400
	}
	if cfg.UploadMultiplier == 0 {
		cfg.UploadMultiplier = 1
	}
	if cfg.DownloadMultiplier == 0 {
		cfg.DownloadMultiplier = 1
	}
	if cfg.PeerTTLSeconds == 0 {
		cfg.PeerTTLSeconds = 3600 // 1h
	}
	if cfg.PeerPurgeIntervalSec == 0 {
		cfg.PeerPurgeIntervalSec = 300 // 5m
	}
	return &cfg, nil
}
