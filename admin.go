package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Guard all admin endpoints with X-Admin-Key
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
    if config.AdminAPIKey == "" {
        http.Error(w, "admin disabled", http.StatusForbidden)
        return false
    }

    key := r.Header.Get("X-Admin-Key")
    if key == "" {
        key = r.URL.Query().Get("key") // allow query string as fallback
    }

    if key != config.AdminAPIKey {
        http.Error(w, "forbidden", http.StatusForbidden)
        return false
    }
    return true
}



// GET /peers?info_hash=... [&page=1&page_size=50]
// Header: X-Admin-Key: <key>
func PeersListHandler(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}

	ihStr := r.URL.Query().Get("info_hash")
	if ihStr == "" {
		http.Error(w, "missing info_hash", http.StatusBadRequest)
		return
	}

	var ih [20]byte
	if len(ihStr) == 40 && isHex(ihStr) {
		b, err := hex.DecodeString(ihStr)
		if err != nil || len(b) != 20 {
			http.Error(w, "invalid info_hash", http.StatusBadRequest)
			return
		}
		copy(ih[:], b)
	} else {
		// percent-encoded accepted
		if dec, err := urlQueryUnescapeSafe(ihStr); err == nil && len(dec) == 20 {
			copy(ih[:], []byte(dec))
		} else {
			http.Error(w, "invalid info_hash", http.StatusBadRequest)
			return
		}
	}

	page := 1
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	pageSize := 50
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			pageSize = n
		}
	}

	total, items := peerStore.ListPaged(ih, page, pageSize)

	type row struct {
		IP          string `json:"ip"`
		Port        int    `json:"port"`
		Seeder      bool   `json:"seeder"`
		Uploaded    uint64 `json:"uploaded"`
		Downloaded  uint64 `json:"downloaded"`
		LastAction  int64  `json:"last_action"`
		Connectable bool   `json:"connectable"`
		Frileech    bool   `json:"freeleech"`
		UserID      int    `json:"user_id"`
		PeerID      string `json:"peer_id"`
	}
	out := struct {
		Total int    `json:"total"`
		Page  int    `json:"page"`
		Size  int    `json:"page_size"`
		Peers []row  `json:"peers"`
		IH    string `json:"infohash"`
	}{
		Total: total, Page: page, Size: pageSize, IH: hex.EncodeToString(ih[:]),
	}

	for _, p := range items {
		out.Peers = append(out.Peers, row{
			IP:          p.IP,
			Port:        p.Port,
			Seeder:      p.Seeder,
			Uploaded:    p.Uploaded,
			Downloaded:  p.Downloaded,
			LastAction:  p.LastAction,
			Connectable: p.Connectable,
			Frileech:    p.Frileech,
			UserID:      p.UserID,
			PeerID:      hex.EncodeToString(p.PeerID[:]),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func urlQueryUnescapeSafe(s string) (string, error) {
	// accept '+' as space in some client encoders
	r := strings.ReplaceAll(s, "+", "%20")
	return url.QueryUnescape(r)
}
