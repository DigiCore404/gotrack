package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Peer struct {
	Torrent     [20]byte
	UserID      int
	PeerID      [20]byte
	IP          string
	Port        int
	Uploaded    uint64
	Downloaded  uint64
	Seeder      bool
	LastAction  int64
	Connectable bool
	Frileech    bool
}

type PeerStore struct {
	mu    sync.RWMutex
	peers map[[20]byte]map[[20]byte]*Peer
}

func NewPeerStore() *PeerStore {
	return &PeerStore{peers: make(map[[20]byte]map[[20]byte]*Peer)}
}


func (ps *PeerStore) SetConnectable(t [20]byte, id [20]byte, ok bool) {
    ps.mu.Lock()
    defer ps.mu.Unlock()
    if m := ps.peers[t]; m != nil {
        if p := m[id]; p != nil {
            p.Connectable = ok
        }
    }
}


func (ps *PeerStore) Get(torrent [20]byte, peerID [20]byte) *Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if m := ps.peers[torrent]; m != nil {
		if p, ok := m[peerID]; ok {
			// return a copy to avoid races if caller modifies it
			cp := *p
			return &cp
		}
	}
	return nil
}

func (ps *PeerStore) AddOrUpdate(p *Peer) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.peers[p.Torrent] == nil {
		ps.peers[p.Torrent] = make(map[[20]byte]*Peer)
	}
	// store a copy to avoid external mutation races
	cp := *p
	ps.peers[p.Torrent][p.PeerID] = &cp
}

func (ps *PeerStore) Remove(torrent [20]byte, peerID [20]byte) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if m := ps.peers[torrent]; m != nil {
		delete(m, peerID)
		if len(m) == 0 {
			delete(ps.peers, torrent)
		}
	}
}

// seedersOnly==true → only seeders; false → all peers
func (ps *PeerStore) GetPeers(torrent [20]byte, seedersOnly bool) []*Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var out []*Peer
	for _, p := range ps.peers[torrent] {
		if !seedersOnly || p.Seeder {
			out = append(out, p)
		}
	}
	return out
}

func (ps *PeerStore) ListPaged(torrent [20]byte, page, pageSize int) (total int, items []*Peer) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var all []*Peer
	for _, p := range ps.peers[torrent] {
		all = append(all, p)
	}
	total = len(all)
	sort.Slice(all, func(i, j int) bool { return all[i].LastAction > all[j].LastAction })
	if pageSize <= 0 {
		pageSize = 50
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start >= total {
		return total, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	items = all[start:end]
	return
}

func (ps *PeerStore) Counts() (torrents int, peers int, seeders int, leechers int) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	torrents = len(ps.peers)
	for _, m := range ps.peers {
		for _, p := range m {
			peers++
			if p.Seeder {
				seeders++
			} else {
				leechers++
			}
		}
	}
	return
}

func (ps *PeerStore) CountsFor(torrent [20]byte) (seeders int, leechers int) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if m := ps.peers[torrent]; m != nil {
		for _, p := range m {
			if p.Seeder {
				seeders++
			} else {
				leechers++
			}
		}
	}
	return
}

// SelectPeers prioritizes opposite role first (seeders want leechers, leechers want seeders), then fills with remaining.
func (ps *PeerStore) SelectPeers(torrent [20]byte, want int, requesterIsSeeder bool) []*Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	m := ps.peers[torrent]
	if m == nil || want <= 0 {
		return nil
	}
	var prim, sec []*Peer
	for _, p := range m {
		if requesterIsSeeder {
			if !p.Seeder {
				prim = append(prim, p)
			} else {
				sec = append(sec, p)
			}
		} else {
			if p.Seeder {
				prim = append(prim, p)
			} else {
				sec = append(sec, p)
			}
		}
	}
	// shuffle both sets
	rand.Shuffle(len(prim), func(i, j int) { prim[i], prim[j] = prim[j], prim[i] })
	rand.Shuffle(len(sec), func(i, j int) { sec[i], sec[j] = sec[j], sec[i] })

	var out []*Peer
	if len(prim) >= want {
		out = prim[:want]
	} else {
		out = append(out, prim...)
		remain := want - len(prim)
		if len(sec) > 0 {
			if remain > len(sec) {
				remain = len(sec)
			}
			out = append(out, sec[:remain]...)
		}
	}
	return out
}

// Snapshot returns a copy slice of all peers (for background writers) without holding the lock during DB ops.
func (ps *PeerStore) Snapshot() []*Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]*Peer, 0, 1024)
	for _, m := range ps.peers {
		for _, p := range m {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out
}

// PurgeStale removes peers whose LastAction is older than now-olderThanSeconds.
// onRemove is called per removed peer (may be nil). Returns number removed.
func (ps *PeerStore) PurgeStale(olderThanSeconds int64, onRemove func(*Peer)) (removed int) {
	now := nowUnix()
	ps.mu.Lock()
	defer ps.mu.Unlock()

	for ih, m := range ps.peers {
		for pid, p := range m {
			if p == nil {
				continue
			}
			if now-p.LastAction > olderThanSeconds {
				if onRemove != nil {
					onRemove(p)
				}
				delete(m, pid)
				removed++
			}
		}
		if len(m) == 0 {
			delete(ps.peers, ih)
		}
	}
	return
}

func CompactPeer(p *Peer) []byte {
	ip := net.ParseIP(p.IP).To4()
	if ip == nil {
		parts := strings.Split(p.IP, ".")
		if len(parts) != 4 {
			return nil
		}
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			n, _ := strconv.Atoi(parts[i])
			b[i] = byte(n)
		}
		ip = b
	}
	out := make([]byte, 6)
	copy(out[:4], ip)
	binary.BigEndian.PutUint16(out[4:], uint16(p.Port))
	return out
}

func nowUnix() int64 { return time.Now().Unix() }
