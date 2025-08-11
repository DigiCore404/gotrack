package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
	_ "github.com/go-sql-driver/mysql"
)

type DB struct {
	db       *sql.DB
	readOnly bool
}

/* ===== FREELEECH WINDOW (settings) ===== */

// LoadFreeleechWindow returns (open?, open_time, close_time, hasWindow?, error)
func (d *DB) LoadFreeleechWindow() (bool, time.Time, time.Time, bool, error) {
	type rec struct {
		ValueS   sql.NullString
		OpenTime sql.NullTime
		Close    sql.NullTime
	}
	var r rec
	row := d.db.QueryRow(`SELECT value_s, open_time, close_time FROM settings WHERE arg='freeleech' LIMIT 1`)
	if err := row.Scan(&r.ValueS, &r.OpenTime, &r.Close); err != nil {
		if err == sql.ErrNoRows {
			return false, time.Time{}, time.Time{}, false, nil
		}
		return false, time.Time{}, time.Time{}, false, err
	}
	has := r.OpenTime.Valid && r.Close.Valid
	open := false
	now := time.Now()
	if r.ValueS.Valid && r.ValueS.String == "open" && has && now.After(r.OpenTime.Time) && now.Before(r.Close.Time) {
		open = true
	}
	var from, to time.Time
	if r.OpenTime.Valid {
		from = r.OpenTime.Time
	}
	if r.Close.Valid {
		to = r.Close.Time
	}
	return open, from, to, has, nil
}

/* ===== INIT / POOL ===== */

func InitDB(cfg DBConfig) (*DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4,utf8",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Name)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	// Pool sizing
	db.SetMaxOpenConns(80)
	db.SetMaxIdleConns(40)
	db.SetConnMaxLifetime(30 * time.Minute)
	return &DB{db: db, readOnly: false}, nil
}

func (d *DB) SetReadOnly(ro bool) { d.readOnly = ro }

/* ===== USERS basics ===== */

// Only load enabled users into the cache
func (d *DB) LoadUsers() (map[string]*User, error) {
	users := make(map[string]*User)
	rows, err := d.db.Query(`
		SELECT id, passkey, enabled, downloadban
		  FROM users
		 WHERE enabled = 'yes'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var u User
		var enabledStr string
		var dlbanInt int
		if err := rows.Scan(&u.ID, &u.Passkey, &enabledStr, &dlbanInt); err != nil {
			continue
		}
		u.Enabled = true            // by WHERE enabled='yes'
		u.DownloadBan = dlbanInt > 0
		users[u.Passkey] = &u
	}
	return users, nil
}

// Also enforce enabled='yes' on cache misses
func (d *DB) GetUserByPasskey(passkey string) (*User, error) {
	row := d.db.QueryRow(`
		SELECT id, passkey, enabled, downloadban
		  FROM users
		 WHERE passkey = ?
		   AND enabled = 'yes'
		 LIMIT 1
	`, passkey)

	var u User
	var enabledStr string
	var dlbanInt int
	if err := row.Scan(&u.ID, &u.Passkey, &enabledStr, &dlbanInt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	u.Enabled = true               // by WHERE enabled='yes'
	u.DownloadBan = dlbanInt > 0
	return &u, nil
}

type UserExtra struct {
	Class      int
	LeechBonus int
}

func (d *DB) GetUserExtra(userID int) (UserExtra, error) {
	var out UserExtra
	row := d.db.QueryRow(`SELECT class, leechbonus FROM users WHERE id = ?`, userID)
	err := row.Scan(&out.Class, &out.LeechBonus)
	return out, err
}

/* ===== PEERS warm-load ===== */

func (d *DB) LoadPeers(ps *PeerStore) error {
	rows, err := d.db.Query(`
        SELECT p.info_hash, p.userid, p.peer_id, p.ip, p.port, p.uploaded, p.downloaded, p.seeder, p.last_action, p.connectable, p.frileech
        FROM peers p
    `)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ihHex string
		var userID int
		var peerIDRaw []byte
		var ip string
		var port uint16
		var uploaded, downloaded uint64
		var seederStr string
		var lastAction time.Time
		var connectable int
		var frileech int

		if err := rows.Scan(&ihHex, &userID, &peerIDRaw, &ip, &port, &uploaded, &downloaded, &seederStr, &lastAction, &connectable, &frileech); err != nil {
			continue
		}

		ihBytes, err := hex.DecodeString(ihHex)
		if err != nil || len(ihBytes) != 20 {
			continue
		}

		var tHash, pID [20]byte
		copy(tHash[:], ihBytes)
		copy(pID[:], peerIDRaw)

		p := &Peer{
			Torrent:     tHash,
			UserID:      userID,
			PeerID:      pID,
			IP:          ip,
			Port:        int(port),
			Uploaded:    uploaded,
			Downloaded:  downloaded,
			Seeder:      seederStr == "yes",
			LastAction:  lastAction.Unix(),
			Connectable: connectable == 1,
			Frileech:    frileech == 1,
		}
		ps.AddOrUpdate(p)
	}
	return nil
}

/* ===== TORRENT STATS (cache source) ===== */

type TorrentStat struct {
	ID        int
	Seeders   int
	Leechers  int
	Completed int
	Frileech  bool
	Added     time.Time
	Section   string // 'new'|'archive'|...
	Size      uint64 // NEW: needed for peers.torrentsize
}

func (d *DB) LoadTorrentStats() (map[[20]byte]TorrentStat, error) {
	rows, err := d.db.Query(`
		SELECT id, info_hash, seeders, leechers, times_completed, frileech, added, section, size
		FROM torrents
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[[20]byte]TorrentStat)
	for rows.Next() {
		var id int
		var ihHex string
		var seeders, leechers, completed int
		var frl int
		var added time.Time
		var section string
		var size uint64
		if err := rows.Scan(&id, &ihHex, &seeders, &leechers, &completed, &frl, &added, &section, &size); err != nil {
			continue
		}
		ihBytes, err := hex.DecodeString(ihHex)
		if err != nil || len(ihBytes) != 20 {
			continue
		}
		var key [20]byte
		copy(key[:], ihBytes)
		out[key] = TorrentStat{
			ID:        id,
			Seeders:   seeders,
			Leechers:  leechers,
			Completed: completed,
			Frileech:  frl == 1,
			Added:     added,
			Section:   section,
			Size:      size,
		}
	}
	return out, nil
}

/* ===== IP bans / settings ===== */

func (d *DB) LoadIPBans() ([]string, error) {
	rows, err := d.db.Query(`SELECT ip FROM ipban`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil && ip != "" {
			out = append(out, ip)
		}
	}
	return out, nil
}

func (d *DB) LoadSitewideFreeleech() (bool, error) {
	var vStr sql.NullString
	var vInt sql.NullInt64
	var open, close sql.NullTime
	row := d.db.QueryRow(`SELECT value_s, value_i, open_time, close_time FROM settings WHERE arg='freeleech' LIMIT 1`)
	_ = row.Scan(&vStr, &vInt, &open, &close)
	now := time.Now()
	if vStr.Valid && vStr.String == "open" && open.Valid && close.Valid && now.After(open.Time) && now.Before(close.Time) {
		return true, nil
	}
	return vInt.Valid && vInt.Int64 > 0, nil
}

/* ===== WRITE PATHS ===== */

func (d *DB) UpsertPeer(p *Peer, userID int, agent string, toGo uint64, seeder bool, connectable bool, frileech bool) error {
	if d.readOnly {
		return nil
	}

	// Info-hash (hex) + required fields per schema
	ihHex := hex.EncodeToString(p.Torrent[:])
	seederStr := "no"
	if seeder {
		seederStr = "yes"
	}
	connInt := 0
	if connectable {
		connInt = 1
	}
	frlInt := 0
	if frileech {
		frlInt = 1
	}
	now := time.Now()

	// Compact 6 bytes ip+port
	cmp := CompactPeer(p)

	// Pull torrent metadata for required columns
	// (ok to miss; defaults will satisfy NOT NULLs)
	var tID int
	section := "new"
	var tSize uint64 = 1
	if ts, ok := torrentStats.Get(p.Torrent); ok {
		tID = ts.ID
		if ts.Section == "new" || ts.Section == "archive" {
			section = ts.Section
		}
		if ts.Size > 0 {
			tSize = ts.Size
		}
	}

	// NOTE: peers has UNIQUE (port, ip, info_hash)
	// Make sure we set ALL required columns: compact, connectable, section, torrentsize, added
	const q = `
INSERT INTO peers
  (info_hash, torrent, peer_id, ip, compact, port,
   uploaded, downloaded, to_go, seeder,
   started, last_action, connectable, userid, agent, finishedat,
   downloadoffset, uploadoffset, frileech, user, mbitupp, mbitner,
   section, leechbonus, torrentsize, added)
VALUES
  (?, ?, ?, ?, ?, ?,
   ?, ?, ?, ?,
   ?, ?, ?, ?, ?, 0,
   0, 0, ?, 0, 0, 0,
   ?, 0, ?, ?)
ON DUPLICATE KEY UPDATE
  uploaded      = VALUES(uploaded),
  downloaded    = VALUES(downloaded),
  to_go         = VALUES(to_go),
  seeder        = VALUES(seeder),
  last_action   = VALUES(last_action),
  connectable   = VALUES(connectable),
  userid        = VALUES(userid),
  agent         = VALUES(agent),
  frileech      = VALUES(frileech),
  section       = VALUES(section),
  torrentsize   = VALUES(torrentsize)
`
	_, err := d.db.Exec(q,
		// INSERT
		ihHex, tID, p.PeerID[:], p.IP, cmp, p.Port,
		p.Uploaded, p.Downloaded, toGo, seederStr,
		now, now, connInt, userID, agent,
		frlInt,
		section, tSize, now,
	)
	if err != nil {
		log.Printf("[DB] UpsertPeer error uid=%d ip=%s port=%d ih=%s: %v", userID, p.IP, p.Port, ihHex, err)
	}
	return err
}

func (d *DB) DeletePeer(p *Peer) error {
	if d.readOnly {
		return nil
	}
	ihHex := hex.EncodeToString(p.Torrent[:])
	_, err := d.db.Exec(`DELETE FROM peers WHERE port = ? AND ip = ? AND info_hash = ?`, p.Port, p.IP, ihHex)
	if err != nil {
		log.Printf("[DB] DeletePeer error ip=%s port=%d ih=%s: %v", p.IP, p.Port, ihHex, err)
	}
	return err
}

func (d *DB) UpdatePeerConnectable(p *Peer, connectable bool) error {
	if d.readOnly {
		return nil
	}
	ihHex := hex.EncodeToString(p.Torrent[:])
	val := 0
	if connectable {
		val = 1
	}
	_, err := d.db.Exec(`UPDATE peers SET connectable = ? WHERE port = ? AND ip = ? AND info_hash = ?`, val, p.Port, p.IP, ihHex)
	return err
}

func (d *DB) UpdateUserStats(userID int, addUp, addUpReal, addDown, addDownReal uint64, nyttSeed, arkivSeed uint64, dip string) error {
	if d.readOnly {
		return nil
	}
	_, err := d.db.Exec(`
		UPDATE users SET
			uploaded = uploaded + ?,
			uploaded_real = uploaded_real + ?,
			nytt_seed = nytt_seed + ?,
			arkiv_seed = arkiv_seed + ?,
			downloaded = downloaded + ?,
			downloaded_real = downloaded_real + ?,
			torrentip = ?
		WHERE id = ?
	`, addUp, addUpReal, nyttSeed, arkivSeed, addDown, addDownReal, dip, userID)
	if err != nil {
		log.Printf("[DB] UpdateUserStats error uid=%d: %v", userID, err)
	}
	return err
}

func (d *DB) OnCompleted(torrentID int, userID int) error {
	if d.readOnly {
		return nil
	}
	if _, err := d.db.Exec(`UPDATE torrents SET seeders = seeders + 1, leechers = GREATEST(leechers - 1, 0), times_completed = times_completed + 1 WHERE id = ?`, torrentID); err != nil {
		return err
	}
	_, _ = d.db.Exec(`UPDATE snatch SET finishedat = NOW() WHERE userid = ? AND torrentid = ?`, userID, torrentID)
	return nil
}

func (d *DB) ClearHnRIfSeeding(userID, torrentID int) {
	if d.readOnly {
		return
	}
	_, _ = d.db.Exec(`
		UPDATE snatch
		   SET hnr = 'no', prehnr = 'no'
		 WHERE userid = ? AND torrentid = ? AND (hnr = 'yes' OR prehnr = 'yes')`,
		userID, torrentID)
}

func (d *DB) BumpSnatchCounters(userID, torrentID int, completed, stopped, updated int) {
	if d.readOnly {
		return
	}
	if completed > 0 {
		_, _ = d.db.Exec(`UPDATE snatch SET timesCompleted = timesCompleted + 1 WHERE userid = ? AND torrentid = ?`, userID, torrentID)
	}
	if stopped > 0 {
		_, _ = d.db.Exec(`UPDATE snatch SET timesStopped = timesStopped + 1 WHERE userid = ? AND torrentid = ?`, userID, torrentID)
	}
	if updated > 0 {
		_, _ = d.db.Exec(`UPDATE snatch SET timesUpdated = timesUpdated + 1 WHERE userid = ? AND torrentid = ?`, userID, torrentID)
	}
}
