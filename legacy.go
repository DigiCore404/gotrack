package main

import (
	"net/http"
	"regexp"
)

// precompiled patterns for legacy paths
var (
	reTrackerPHPAnnounce = regexp.MustCompile(`^/tracker\.php/([a-fA-F0-9]{32})/announce/?$`)
	reTrackerPHPScrape   = regexp.MustCompile(`^/tracker\.php/([a-fA-F0-9]{32})/scrape/?$`)

	reAnnouncePath = regexp.MustCompile(`^/announce/([a-fA-F0-9]{32})/?$`)
	reScrapePath   = regexp.MustCompile(`^/scrape/([a-fA-F0-9]{32})/?$`)
)

// LegacyRouter intercepts legacy path styles and forwards to our real handlers.
func LegacyRouter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// /tracker.php/<passkey>/announce  -> /announce?passkey=...
		if m := reTrackerPHPAnnounce.FindStringSubmatch(path); m != nil {
			pass := m[1]
			q := r.URL.Query()
			q.Set("passkey", pass) // force-set
			r.URL.RawQuery = q.Encode()
			r.URL.Path = "/announce"
			AnnounceHandler(w, r)
			return
		}

		// /tracker.php/<passkey>/scrape -> /scrape?passkey=...
		if m := reTrackerPHPScrape.FindStringSubmatch(path); m != nil {
			pass := m[1]
			q := r.URL.Query()
			q.Set("passkey", pass)
			r.URL.RawQuery = q.Encode()
			r.URL.Path = "/scrape"
			ScrapeHandler(w, r)
			return
		}

		// /announce/<passkey> -> /announce?passkey=...
		if m := reAnnouncePath.FindStringSubmatch(path); m != nil {
			pass := m[1]
			q := r.URL.Query()
			q.Set("passkey", pass)
			r.URL.RawQuery = q.Encode()
			r.URL.Path = "/announce"
			AnnounceHandler(w, r)
			return
		}

		// /scrape/<passkey> -> /scrape?passkey=...
		if m := reScrapePath.FindStringSubmatch(path); m != nil {
			pass := m[1]
			q := r.URL.Query()
			q.Set("passkey", pass)
			r.URL.RawQuery = q.Encode()
			r.URL.Path = "/scrape"
			ScrapeHandler(w, r)
			return
		}

		// Not a legacy route, continue
		next.ServeHTTP(w, r)
	})
}

// Helper: wrap mux in main.go with withLegacy(mux)
func withLegacy(h http.Handler) http.Handler {
	return LegacyRouter(h)
}
