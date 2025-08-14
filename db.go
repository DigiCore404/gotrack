package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
	mysql "github.com/go-sql-driver/mysql"
	"net"
    "sync/atomic"

)

type DB struct {
	db       *sql.DB
	readOnly bool
}









// ---- async DB write queue ----
type dbJob interface{ run(*DB) }
type dbFunc func(*DB)
func (f dbFunc) run(d *DB) { f(d) }

var (
	writeQ         chan dbJob
	writeQClosed   = make(chan struct{}) // indicates "started" after close
	lastDBQWarnSec int64
)

// Start a fixed number of DB workers and a big buffered queue.
// Call this once from main() after InitDB.
func StartDBWorkers(d *DB, workers int, queueSize int) {
	if workers <= 0 {
		workers = 12
	}
	if queueSize <= 0 {
		queueSize = 200_000
	}
	writeQ = make(chan dbJob, queueSize)
	for i := 0; i < workers; i++ {
		go func() {
			for job := range writeQ {
				func() { // protect worker from panics
					defer func() { _ = recover() }()
					job.run(d)
				}()
			}
		}()
	}
	close(writeQClosed) // signal "started"
}

// Non-blocking enqueue with tiny wait; if saturated, run synchronously.
// This guarantees we DO NOT DROP work.
func EnqueueDB(f dbFunc) {
	// Fast path: queue has room
	select {
	case writeQ <- f:
		return
	default:
	}

	// Brief grace period (reduces sync fallback under bursts)
	t := time.NewTimer(3 * time.Millisecond)
	select {
	case writeQ <- f:
		if !t.Stop() {
			<-t.C
		}
		return
	case <-t.C:
		// fall through
	}

	// No room: execute synchronously to avoid data loss
	// 'db' is the package-level *DB set in main.go
	if db != nil {
		f(db)
	} else {
		// extreme fallback: run on a goroutine (still not dropped)
		go f(db)
	}

	// Rate-limit the warning (once every 5s)
	now := time.Now().Unix()
	if atomic.LoadInt64(&lastDBQWarnSec)+5 <= now {
		atomic.StoreInt64(&lastDBQWarnSec, now)
		log.Printf("[DBQ] saturated; ran job synchronously (queue=%d)", len(writeQ))
	}
}






// Only prints MySQL driver logs when config.DebugAnnounce is true
type mysqlDebugLogger struct{}

func (mysqlDebugLogger) Print(v ...interface{}) {
    if config != nil && config.DebugAnnounce {
        log.Print(v...) // driver already prefixes with [mysql]
    }
}

func (d *DB) GetSnatchLastAction(userID, torrentID int) (time.Time, bool) {
    var t time.Time
    err := d.db.QueryRow(
        `SELECT lastaction FROM snatch WHERE userid=? AND torrentid=? LIMIT 1`,
        userID, torrentID,
    ).Scan(&t)
    if err != nil {
        return time.Time{}, false
    }
    return t, true
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

       // Enable conditional driver logging
       mysql.SetLogger(mysqlDebugLogger{})

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4,utf8",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Name)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	// Pool sizing

db.SetMaxOpenConns(48)        // total parallel MySQL conns allowed
db.SetMaxIdleConns(48)        // keep same as open for reuse
db.SetConnMaxLifetime(2 * time.Minute)  // rotate conns to avoid long-lived


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
	Class          int
	LeechBonus     int
	MbitUpp        int
	MbitNer        int
	LeechStartUnix int64
}

func (d *DB) GetUserExtra(userID int) (UserExtra, error) {
	var out UserExtra
	row := d.db.QueryRow(`
		SELECT class,
		       leechbonus,
		       CAST(mbitupp AS SIGNED),
		       CAST(mbitner  AS SIGNED),
		       UNIX_TIMESTAMP(leechstart)
		  FROM users
		 WHERE id = ?`,
		userID,
	)
	err := row.Scan(&out.Class, &out.LeechBonus, &out.MbitUpp, &out.MbitNer, &out.LeechStartUnix)
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

type torrentMeta struct {
	ID      int
	Frl     bool
	Section string
	Size    uint64
	Added   time.Time
}

func (d *DB) getTorrentMetaByHash(ihHex string) (torrentMeta, error) {
	var m torrentMeta
	var frl int
	err := d.db.QueryRow(`
		SELECT id, frileech, section, size, added
		  FROM torrents
		 WHERE info_hash = ?
		 LIMIT 1`, ihHex).
		Scan(&m.ID, &frl, &m.Section, &m.Size, &m.Added)
	m.Frl = frl == 1
	return m, err
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



func max64(a, b int64) int64 {
	if a > b { return a }
	return b
}


/* ===== WRITE PATHS ===== */

func (d *DB) UpsertSnatch(
	userID, torrentID int,
	ip string, port int, agent string,
	connectable bool,
	timesStarted, timesCompleted, timesUpdated, timesStopped int,
	addUp, addDown uint64,
	seeder bool,
) error {
	if d.readOnly {
		return nil
	}

	connInt := 0
	if connectable {
		connInt = 1
	}
	seederInt := 0
	if seeder {
		seederInt = 1
	}

	if config.DebugAnnounce {
		log.Printf("[UpsertSnatch] uid=%d tid=%d ip=%s port=%d agent=%s conn=%d seeder=%v addUp=%d addDown=%d",
			userID, torrentID, ip, port, agent, connInt, seeder, addUp, addDown)
	}

	// UPDATE first — PHP style seedtime update (no cap, always accurate)
	res, err := d.db.Exec(`
        UPDATE snatch
           SET timesStarted   = timesStarted   + ?,
               timesCompleted = timesCompleted + ?,
               timesUpdated   = timesUpdated   + ?,
               timesStopped   = timesStopped   + ?,
               uploaded       = uploaded + ?,
               downloaded     = downloaded + ?,
               seedtime       = seedtime + IF(?, GREATEST(TIMESTAMPDIFF(SECOND, lastaction, NOW()), 0), 0),
               connectable    = ?,
               ip             = ?,
               port           = ?,
               agent          = ?,
               lastaction     = NOW()
         WHERE userid    = ?
           AND torrentid = ?
    `,
		timesStarted, timesCompleted, timesUpdated, timesStopped,
		addUp, addDown,
		seederInt,
		connInt,
		ip, port, agent,
		userID, torrentID,
	)
	if err != nil {
		if config.DebugAnnounce {
			log.Printf("[UpsertSnatch] UPDATE error: %v", err)
		}
		return err
	}

	if aff, _ := res.RowsAffected(); aff > 0 {
		if config.DebugAnnounce {
			log.Printf("[UpsertSnatch] Updated existing snatch row for uid=%d tid=%d", userID, torrentID)
		}
		return nil
	}

	// INSERT if no row — ON DUP to survive races and guarantee presence
	if config.DebugAnnounce {
		log.Printf("[UpsertSnatch] No existing row, inserting/merging snatch for uid=%d tid=%d", userID, torrentID)
	}
	_, err = d.db.Exec(`
        INSERT INTO snatch (
            userid, torrentid, ip, port, agent, connectable,
            klar, lastaction,
            timesStarted, timesCompleted, timesUpdated, timesStopped,
            uploaded, downloaded, seedtime, seeding, hnr, prehnr, immune
        ) VALUES (
            ?, ?, ?, ?, ?, ?,
            NOW(), NOW(),
            ?, ?, ?, ?,
            ?, ?, 0, 'no', 'no', 'no', 'no'
        )
        ON DUPLICATE KEY UPDATE
            ip = VALUES(ip),
            port = VALUES(port),
            agent = VALUES(agent),
            connectable = VALUES(connectable),
            lastaction = VALUES(lastaction),
            timesStarted   = timesStarted   + VALUES(timesStarted),
            timesCompleted = timesCompleted + VALUES(timesCompleted),
            timesUpdated   = timesUpdated   + VALUES(timesUpdated),
            timesStopped   = timesStopped   + VALUES(timesStopped),
            uploaded       = uploaded       + VALUES(uploaded),
            downloaded     = downloaded     + VALUES(downloaded)
    `,
		userID, torrentID, ip, port, agent, connInt,
		timesStarted, timesCompleted, timesUpdated, timesStopped,
		addUp, addDown,
	)
	if err != nil {
		if config.DebugAnnounce {
			log.Printf("[UpsertSnatch] INSERT/ON DUP error: %v", err)
		}
		return err
	}

	if config.DebugAnnounce {
		log.Printf("[UpsertSnatch] Inserted/merged snatch row for uid=%d tid=%d", userID, torrentID)
	}
	return nil
}


func (d *DB) UpsertPeer(
	p *Peer,
	userID int,
	agent string,
	toGo uint64,
	seeder bool,
	connectable bool, // current flag from memory; we also try a quick dial below
	frileech bool,
	event string,
) error {
	if d.readOnly {
		return nil
	}

	// --- quick TCP dial so "connectable" is visible immediately (keep this)
	connInt := 0
	addr := net.JoinHostPort(p.IP, fmt.Sprintf("%d", p.Port))
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		connInt = 1
		_ = c.Close()
	}

	ihHex := hex.EncodeToString(p.Torrent[:])

	seederStr := "no"
	if seeder {
		seederStr = "yes"
	}
	frlInt := 0
	if frileech {
		frlInt = 1
	}

	// 6-byte compact (IPv4) fallback to zeros to satisfy NOT NULL
	cmp := CompactPeer(p)
	if cmp == nil || len(cmp) != 6 {
		cmp = make([]byte, 6)
	}

	// ---- Torrent meta (cache → DB fallback) ----
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
	} else {
		if err := d.db.QueryRow(`SELECT id, section, size FROM torrents WHERE info_hash=? LIMIT 1`,
			ihHex).Scan(&tID, &section, &tSize); err != nil {
			if config.DebugAnnounce {
				log.Printf("[ANNOUNCE PEERS] meta DB scan ih=%s err=%v", ihHex, err)
			}
		}
	}

	// see what we resolved
	if config.DebugAnnounce {
		log.Printf("[ANNOUNCE PEERS] meta lookup ih=%s -> tID=%d section=%s size=%d", ihHex, tID, section, tSize)
	}

	if tID == 0 {
		if config.DebugAnnounce {
			log.Printf("[ANNOUNCE PEERS] unregistered torrent ih=%s (refusing to insert with tID=0)", ihHex)
		}
		return fmt.Errorf("unregistered torrent")
	}

	// ---- finishedat gate like your PHP, but also handle "arrive-as-seeder" case ----
	shouldSetFinished := false
	var seederDB string
	if err := d.db.QueryRow(
		`SELECT seeder FROM peers WHERE port=? AND ip=? AND info_hash=? LIMIT 1`,
		p.Port, p.IP, ihHex,
	).Scan(&seederDB); err == nil {
		// transition no->yes, or client sends explicit completed
		if seeder && seederDB == "no" {
			shouldSetFinished = true
		} else if event == "completed" && seeder {
			shouldSetFinished = true
		}
	} else if err != sql.ErrNoRows && config.DebugAnnounce {
		log.Printf("[UpsertPeer] pre-check seeder scan err ih=%s ip=%s port=%d err=%v", ihHex, p.IP, p.Port, err)
	}

	// ---- UPDATE (no DB-side speed math, do NOT touch offsets here) ----
	qUpdate := `
UPDATE peers
   SET uploaded    = ?,
       downloaded  = ?,
       to_go       = ?,
       seeder      = ?,
       last_action = NOW(),
       ip          = ?,
       connectable = ?,
       userid      = ?,
       agent       = ?,
       frileech    = ?,
       section     = ?,
       torrentsize = ?`
	if shouldSetFinished {
		qUpdate += `, finishedat = UNIX_TIMESTAMP(NOW())`
	}
	qUpdate += `
 WHERE port = ? AND ip = ? AND info_hash = ?`

	res, err := d.db.Exec(qUpdate,
		p.Uploaded, p.Downloaded, toGo, seederStr,
		p.IP, connInt, userID, agent, frlInt, section, tSize,
		p.Port, p.IP, ihHex,
	)
	if err != nil && config.DebugAnnounce {
		log.Printf("[UpsertPeer][UPDATE] err=%v ih=%s ip=%s port=%d", err, ihHex, p.IP, p.Port)
	}
	if err == nil {
		if aff, _ := res.RowsAffected(); aff > 0 {
			if config.DebugAnnounce {
				log.Printf("[UpsertPeer][UPDATE] ok ih=%s ip=%s port=%d uid=%d seed=%s conn=%d",
					ihHex, p.IP, p.Port, userID, seederStr, connInt)
			}
			return nil
		}
	}

	// ---- INSERT (initialize offsets ONCE like your PHP)
	// KEY FIX: if peer arrives as seeder (left==0), set finishedat NOW at INSERT.
	finishedAt := int64(0)
	if seeder {
		finishedAt = time.Now().Unix()
	}

	const qInsert = `
INSERT INTO peers
  (info_hash, torrent, peer_id, ip, compact, port,
   uploaded, downloaded, to_go, seeder,
   started, last_action, connectable, userid, agent, finishedat,
   downloadoffset, uploadoffset, frileech, user, mbitupp, mbitner,
   section, leechbonus, torrentsize, added)
VALUES
  (?, ?, ?, ?, ?, ?,
   ?, ?, ?, ?,
   NOW(), NOW(), ?, ?, ?, ?,
   ?, ?, ?, 0, 0, 0,
   ?, 0, ?, NOW())
ON DUPLICATE KEY UPDATE
  last_action = NOW(),
  port        = VALUES(port),
  ip          = VALUES(ip),
  userid      = VALUES(userid),
  agent       = VALUES(agent),
  seeder      = VALUES(seeder),
  connectable = VALUES(connectable)`

	_, err = d.db.Exec(qInsert,
		ihHex, tID, p.PeerID[:], p.IP, cmp, p.Port,
		p.Uploaded, p.Downloaded, toGo, seederStr,
		connInt, userID, agent, finishedAt,
		// initialize offsets at first sight — do NOT update them later
		p.Downloaded, p.Uploaded,
		frlInt,
		section, tSize,
	)
	if err != nil {
		if config.DebugAnnounce {
			log.Printf("[UpsertPeer][INSERT] err=%v ih=%s ip=%s port=%d uid=%d", err, ihHex, p.IP, p.Port, userID)
		}
		return err
	}
	if config.DebugAnnounce {
		log.Printf("[UpsertPeer][INSERT] ok ih=%s ip=%s port=%d uid=%d tID=%d seed=%s conn=%d finishedat=%d",
			ihHex, p.IP, p.Port, userID, tID, seederStr, connInt, finishedAt)
	}
	return nil
}





// RecountTorrentCountsByHash recomputes seeders/leechers from peers and updates torrents.
// Uses MySQL subqueries in a single UPDATE so it’s consistent and fast.
func (d *DB) RecountTorrentCountsByHash(ihHex string) error {
	if d.readOnly {
		return nil
	}
	_, err := d.db.Exec(
		`UPDATE torrents
		   SET seeders  = (SELECT COUNT(*) FROM peers WHERE info_hash = ? AND seeder = 'yes'),
		       leechers = (SELECT COUNT(*) FROM peers WHERE info_hash = ? AND seeder = 'no')
		 WHERE info_hash = ?`,
		ihHex, ihHex, ihHex,
	)
	return err
}


func (d *DB) DeletePeer(p *Peer) error {
	if d.readOnly {
		return nil
	}
	ihHex := hex.EncodeToString(p.Torrent[:])

	// We need the current row's torrent id and seeder flag to adjust counts,
	// just like the PHP tracker does.
	var tID int
	var seederStr string
	row := d.db.QueryRow(`SELECT torrent, seeder FROM peers WHERE port = ? AND ip = ? AND info_hash = ? LIMIT 1`,
		p.Port, p.IP, ihHex)
	_ = row.Scan(&tID, &seederStr)

	_, err := d.db.Exec(`DELETE FROM peers WHERE port = ? AND ip = ? AND info_hash = ?`, p.Port, p.IP, ihHex)
	if err != nil {
		log.Printf("[DB] DeletePeer error ip=%s port=%d ih=%s: %v", p.IP, p.Port, ihHex, err)
		return err
	}

	// Decrement the torrent counts if we knew the row we deleted
	if tID > 0 {
		if seederStr == "yes" {
			_, _ = d.db.Exec(`UPDATE torrents SET seeders = GREATEST(seeders - 1, 0) WHERE id = ?`, tID)
		} else {
			_, _ = d.db.Exec(`UPDATE torrents SET leechers = GREATEST(leechers - 1, 0) WHERE id = ?`, tID)
		}
	}

	return nil
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

res, err := d.db.Exec(`UPDATE peers SET connectable=? WHERE port=? AND ip=? AND info_hash=?`, val, p.Port, p.IP, ihHex)
if err == nil {
    if n, _ := res.RowsAffected(); n == 0 {
        time.Sleep(200 * time.Millisecond)
        _, _ = d.db.Exec(`UPDATE peers SET connectable=? WHERE port=? AND ip=? AND info_hash=?`, val, p.Port, p.IP, ihHex)
    }
}

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
	// Only times_completed and finishedat here.
	if _, err := d.db.Exec(`UPDATE torrents SET times_completed = times_completed + 1 WHERE id = ?`, torrentID); err != nil {
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
