package panel

import (
	"database/sql"
	"fmt"
	"log"

	"malicious-detector/internal/shared"

	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sql.DB
}

func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	database := &Database{db: db}
	if err := database.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}

	return database, nil
}

func (d *Database) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS detectors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token TEXT UNIQUE NOT NULL,
			created DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			status TEXT DEFAULT 'offline',
			ip TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS malicious_ips (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL UNIQUE,
			source TEXT NOT NULL,
			source_type TEXT NOT NULL,
			weight INTEGER DEFAULT 1,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			count INTEGER DEFAULT 1,
			reason TEXT,
			ban_time INTEGER DEFAULT 1440,
			active BOOLEAN DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS external_feeds (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			url TEXT NOT NULL,
			update_freq INTEGER DEFAULT 60,
			last_update DATETIME DEFAULT CURRENT_TIMESTAMP,
			active BOOLEAN DEFAULT 1,
			format TEXT DEFAULT 'plain',
			description TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_weight ON malicious_ips(weight DESC, last_seen DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_active ON malicious_ips(active)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_ip ON malicious_ips(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_source_type ON malicious_ips(source_type)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_last_seen ON malicious_ips(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_malicious_ips_ban_time ON malicious_ips(ban_time)`,
		`CREATE INDEX IF NOT EXISTS idx_detectors_status ON detectors(status)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %s, error: %v", query, err)
		}
	}

	log.Println("Database tables created successfully")
	return nil
}

// Detector methods
func (d *Database) CreateDetector(detector *shared.DetectorConfig) error {
	query := `INSERT INTO detectors (name, token, created, last_seen, status, ip) 
			  VALUES (?, ?, ?, ?, ?, ?)`

	result, err := d.db.Exec(query, detector.Name, detector.Token,
		detector.Created, detector.LastSeen, detector.Status, detector.IP)

	if err != nil {
		return err
	}

	// Get the auto-generated ID
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	detector.ID = int(id)
	return nil
}

func (d *Database) GetDetector(id int) (*shared.DetectorConfig, error) {
	query := `SELECT id, name, token, created, last_seen, status, ip FROM detectors WHERE id = ?`

	detector := &shared.DetectorConfig{}
	err := d.db.QueryRow(query, id).Scan(
		&detector.ID, &detector.Name, &detector.Token,
		&detector.Created, &detector.LastSeen, &detector.Status, &detector.IP,
	)

	if err != nil {
		return nil, err
	}

	return detector, nil
}

func (d *Database) GetDetectorByToken(token string) (*shared.DetectorConfig, error) {
	query := `SELECT id, name, token, created, last_seen, status, ip FROM detectors WHERE token = ?`

	detector := &shared.DetectorConfig{}
	err := d.db.QueryRow(query, token).Scan(
		&detector.ID, &detector.Name, &detector.Token,
		&detector.Created, &detector.LastSeen, &detector.Status, &detector.IP,
	)

	if err != nil {
		return nil, err
	}

	return detector, nil
}

func (d *Database) GetAllDetectors() ([]*shared.DetectorConfig, error) {
	query := `SELECT id, name, token, created, last_seen, status, ip FROM detectors ORDER BY name`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var detectors []*shared.DetectorConfig
	for rows.Next() {
		detector := &shared.DetectorConfig{}
		err := rows.Scan(
			&detector.ID, &detector.Name, &detector.Token,
			&detector.Created, &detector.LastSeen, &detector.Status, &detector.IP,
		)
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, detector)
	}

	return detectors, nil
}

func (d *Database) UpdateDetectorStatus(id int, status, ip string) error {
	query := `UPDATE detectors SET status = ?, ip = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := d.db.Exec(query, status, ip, id)
	return err
}

func (d *Database) DeleteDetector(id int) error {
	query := `DELETE FROM detectors WHERE id = ?`
	_, err := d.db.Exec(query, id)
	return err
}

// MaliciousIP methods
func (d *Database) AddMaliciousIP(ip *shared.MaliciousIP) error {
	// Try to update existing IP record (regardless of source)
	updateQuery := `UPDATE malicious_ips SET 
					last_seen = ?, 
					count = count + 1, 
					weight = CASE WHEN ? > weight THEN ? ELSE weight END,
					ban_time = CASE WHEN ? > ban_time OR ban_time = 0 THEN ? ELSE ban_time END,
					source = CASE WHEN ? > weight THEN ? ELSE source END,
					source_type = CASE WHEN ? > weight THEN ? ELSE source_type END,
					reason = ?,
					active = 1 
					WHERE ip = ?`

	result, err := d.db.Exec(updateQuery,
		ip.LastSeen,          // last_seen
		ip.Weight, ip.Weight, // weight comparison and update
		ip.BanTime, ip.BanTime, // ban_time comparison and update
		ip.Weight, ip.Source, // source update if higher weight
		ip.Weight, ip.SourceType, // source_type update if higher weight
		ip.Reason, // reason (always update)
		ip.IP)     // WHERE condition

	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	// If no rows were updated, insert new record
	if rowsAffected == 0 {
		insertQuery := `INSERT INTO malicious_ips 
						(ip, source, source_type, weight, first_seen, last_seen, count, reason, ban_time, active)
						VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

		_, err = d.db.Exec(insertQuery, ip.IP, ip.Source, ip.SourceType, ip.Weight,
			ip.FirstSeen, ip.LastSeen, ip.Count, ip.Reason, ip.BanTime, ip.Active)
	}

	return err
}

func (d *Database) GetMaliciousIPs(limit int) ([]*shared.MaliciousIP, error) {
	query := `SELECT id, ip, source, source_type, weight, first_seen, last_seen, count, reason, ban_time, active 
			  FROM malicious_ips 
			  WHERE active = 1 
			  ORDER BY weight DESC, last_seen DESC`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*shared.MaliciousIP
	for rows.Next() {
		ip := &shared.MaliciousIP{}
		err := rows.Scan(
			&ip.ID, &ip.IP, &ip.Source, &ip.SourceType, &ip.Weight,
			&ip.FirstSeen, &ip.LastSeen, &ip.Count, &ip.Reason, &ip.BanTime, &ip.Active,
		)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func (d *Database) DeactivateMaliciousIP(id int) error {
	query := `UPDATE malicious_ips SET active = 0 WHERE id = ?`
	_, err := d.db.Exec(query, id)
	return err
}

func (d *Database) GetMaliciousIPCount() (int, error) {
	query := `SELECT COUNT(*) FROM malicious_ips WHERE active = 1`
	var count int
	err := d.db.QueryRow(query).Scan(&count)
	return count, err
}

// Deactivates IPs that have exceeded their ban time
// ban_time = 0 means permanent ban (never expires)
func (d *Database) ExpireOldMaliciousIPs() error {
	query := `UPDATE malicious_ips SET active = 0 
			  WHERE active = 1 
			  AND ban_time > 0
			  AND datetime(last_seen, '+' || ban_time || ' minutes') <= datetime('now')`

	result, err := d.db.Exec(query)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected > 0 {
		log.Printf("Expired %d malicious IPs that exceeded their ban time", rowsAffected)
	}

	return nil
}

// ExternalFeed methods
func (d *Database) AddExternalFeed(feed *shared.ExternalFeed) error {
	query := `INSERT INTO external_feeds (name, url, update_freq, last_update, active, format, description)
			  VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := d.db.Exec(query, feed.Name, feed.URL, feed.UpdateFreq,
		feed.LastUpdate, feed.Active, feed.Format, feed.Description)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	feed.ID = int(id)
	return nil
}

func (d *Database) GetExternalFeeds() ([]*shared.ExternalFeed, error) {
	query := `SELECT id, name, url, update_freq, last_update, active, format, description 
			  FROM external_feeds ORDER BY name`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var feeds []*shared.ExternalFeed
	for rows.Next() {
		feed := &shared.ExternalFeed{}
		err := rows.Scan(
			&feed.ID, &feed.Name, &feed.URL, &feed.UpdateFreq,
			&feed.LastUpdate, &feed.Active, &feed.Format, &feed.Description,
		)
		if err != nil {
			return nil, err
		}
		feeds = append(feeds, feed)
	}

	return feeds, nil
}

func (d *Database) UpdateExternalFeedLastUpdate(id int) error {
	query := `UPDATE external_feeds SET last_update = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := d.db.Exec(query, id)
	return err
}

func (d *Database) DeleteExternalFeed(id int) error {
	query := `DELETE FROM external_feeds WHERE id = ?`
	_, err := d.db.Exec(query, id)
	return err
}

func (d *Database) Close() error {
	return d.db.Close()
}
