// Package store keeps assets, scan results, findings and events in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the database.
type Store struct {
	db *sql.DB
}

var migrations = []string{
	`CREATE TABLE assets (
		id INTEGER PRIMARY KEY,
		kind TEXT NOT NULL,
		value TEXT NOT NULL UNIQUE,
		token TEXT NOT NULL,
		verified_at TIMESTAMP,
		verify_method TEXT NOT NULL DEFAULT '',
		parent_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
		allowed_ports TEXT NOT NULL DEFAULT '',
		expires_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL
	)`,
	`CREATE TABLE runs (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		check_name TEXT NOT NULL,
		ran_at TIMESTAMP NOT NULL,
		error TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (asset_id, check_name)
	)`,
	`CREATE TABLE ports (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		banner TEXT NOT NULL DEFAULT '',
		first_seen TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL,
		PRIMARY KEY (asset_id, host, port)
	)`,
	`CREATE TABLE certs (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		subject TEXT NOT NULL DEFAULT '',
		issuer TEXT NOT NULL DEFAULT '',
		not_after TIMESTAMP,
		version TEXT NOT NULL DEFAULT '',
		problem TEXT NOT NULL DEFAULT '',
		checked_at TIMESTAMP NOT NULL,
		PRIMARY KEY (asset_id, host, port)
	)`,
	`CREATE TABLE dns (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		record TEXT NOT NULL,
		PRIMARY KEY (asset_id, record)
	)`,
	`CREATE TABLE subdomains (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		first_seen TIMESTAMP NOT NULL,
		PRIMARY KEY (asset_id, name)
	)`,
	`CREATE TABLE findings (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		key TEXT NOT NULL,
		severity INTEGER NOT NULL,
		title TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		first_seen TIMESTAMP NOT NULL,
		PRIMARY KEY (asset_id, key)
	)`,
	`CREATE TABLE events (
		id INTEGER PRIMARY KEY,
		asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
		severity INTEGER NOT NULL,
		title TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP NOT NULL
	)`,
	`CREATE INDEX events_created ON events(created_at DESC)`,
	`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
}

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(v), 0) FROM schema_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (v) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Asset kinds.
const (
	Domain = "domain"
	IP     = "ip"
)

// Asset is a domain or IP being watched.
type Asset struct {
	ID           int64
	Kind         string
	Value        string
	Token        string
	VerifiedAt   *time.Time
	VerifyMethod string
	ParentID     *int64
	AllowedPorts []int
	ExpiresAt    *time.Time
	CreatedAt    time.Time
}

// Verified reports whether active scans may run.
func (a Asset) Verified() bool { return a.VerifiedAt != nil }

// Allowed reports whether port is on the allowlist.
func (a Asset) Allowed(port int) bool {
	for _, p := range a.AllowedPorts {
		if p == port {
			return true
		}
	}
	return false
}

// ErrNotFound is returned when a row doesn't exist.
var ErrNotFound = errors.New("not found")

const assetCols = `id, kind, value, token, verified_at, verify_method, parent_id, allowed_ports, expires_at, created_at`

func scanAsset(row interface{ Scan(...any) error }) (Asset, error) {
	var a Asset
	var verified, expires sql.NullTime
	var parent sql.NullInt64
	var ports string
	if err := row.Scan(&a.ID, &a.Kind, &a.Value, &a.Token, &verified, &a.VerifyMethod, &parent, &ports, &expires, &a.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return a, ErrNotFound
		}
		return a, err
	}
	if verified.Valid {
		t := verified.Time
		a.VerifiedAt = &t
	}
	if expires.Valid {
		t := expires.Time
		a.ExpiresAt = &t
	}
	if parent.Valid {
		p := parent.Int64
		a.ParentID = &p
	}
	a.AllowedPorts = ParsePorts(ports)
	return a, nil
}

// ParsePorts reads "22, 80,443" into a sorted, de-duplicated list. Invalid entries are skipped.
func ParsePorts(s string) []int {
	seen := map[int]bool{}
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		var p int
		if _, err := fmt.Sscanf(f, "%d", &p); err == nil && p > 0 && p < 65536 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sortInts(out)
	return out
}

// FormatPorts is the inverse of ParsePorts.
func FormatPorts(ps []int) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ", ")
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// AddAsset inserts a new asset.
func (s *Store) AddAsset(ctx context.Context, a Asset) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO assets (kind, value, token, verified_at, verify_method, parent_id, allowed_ports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Kind, a.Value, a.Token, a.VerifiedAt, a.VerifyMethod, a.ParentID, FormatPorts(a.AllowedPorts), time.Now().UTC())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, fmt.Errorf("%s is already being watched", a.Value)
		}
		return 0, err
	}
	return res.LastInsertId()
}

// Asset returns one asset.
func (s *Store) Asset(ctx context.Context, id int64) (Asset, error) {
	return scanAsset(s.db.QueryRowContext(ctx, `SELECT `+assetCols+` FROM assets WHERE id = ?`, id))
}

// Assets returns every asset, parents before their children.
func (s *Store) Assets(ctx context.Context) ([]Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+assetCols+` FROM assets ORDER BY COALESCE(parent_id, id), parent_id IS NOT NULL, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkVerified records a successful ownership check.
func (s *Store) MarkVerified(ctx context.Context, id int64, method string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE assets SET verified_at = ?, verify_method = ? WHERE id = ?`, time.Now().UTC(), method, id)
	return err
}

// SetAllowedPorts replaces an asset's allowlist.
func (s *Store) SetAllowedPorts(ctx context.Context, id int64, ports []int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE assets SET allowed_ports = ? WHERE id = ?`, FormatPorts(ports), id)
	return err
}

// SetExpiry records a domain's registration expiry.
func (s *Store) SetExpiry(ctx context.Context, id int64, t *time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE assets SET expires_at = ? WHERE id = ?`, t, id)
	return err
}

// DeleteAsset removes an asset and everything recorded for it.
func (s *Store) DeleteAsset(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
	return err
}

// LastRun returns when a check last ran for an asset.
func (s *Store) LastRun(ctx context.Context, assetID int64, check string) (time.Time, string, error) {
	var t time.Time
	var e string
	err := s.db.QueryRowContext(ctx, `SELECT ran_at, error FROM runs WHERE asset_id = ? AND check_name = ?`, assetID, check).Scan(&t, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, "", nil
	}
	return t, e, err
}

// RecordRun stores that a check ran, with its error if any.
func (s *Store) RecordRun(ctx context.Context, assetID int64, check string, runErr error) error {
	msg := ""
	if runErr != nil {
		msg = runErr.Error()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO runs (asset_id, check_name, ran_at, error) VALUES (?, ?, ?, ?)
		 ON CONFLICT (asset_id, check_name) DO UPDATE SET ran_at = excluded.ran_at, error = excluded.error`,
		assetID, check, time.Now().UTC(), msg)
	return err
}

// Setting returns a setting or def.
func (s *Store) Setting(ctx context.Context, key, def string) string {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

// SetSetting stores a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
