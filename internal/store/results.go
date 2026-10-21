package store

import (
	"context"
	"database/sql"
	"time"
)

// Severity orders findings and events.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "info"
	}
	return sevNames[s]
}

// ParseSeverity turns a name into a Severity, defaulting to Medium.
func ParseSeverity(v string) Severity {
	for i, n := range sevNames {
		if n == v {
			return Severity(i)
		}
	}
	return Medium
}

// Port is an open port seen on a host.
type Port struct {
	Host      string
	Port      int
	Banner    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Ports returns the open ports recorded for an asset.
func (s *Store) Ports(ctx context.Context, assetID int64) ([]Port, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, port, banner, first_seen, last_seen FROM ports WHERE asset_id = ? ORDER BY host, port`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Port
	for rows.Next() {
		var p Port
		if err := rows.Scan(&p.Host, &p.Port, &p.Banner, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ReplacePorts stores the latest open ports for one host, keeping first_seen for ports that stay open.
func (s *Store) ReplacePorts(ctx context.Context, assetID int64, host string, open []Port) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	keep := map[int]bool{}
	for _, p := range open {
		keep[p.Port] = true
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO ports (asset_id, host, port, banner, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (asset_id, host, port) DO UPDATE SET banner = excluded.banner, last_seen = excluded.last_seen`,
			assetID, host, p.Port, p.Banner, now, now); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT port FROM ports WHERE asset_id = ? AND host = ?`, assetID, host)
	if err != nil {
		return err
	}
	var gone []int
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		if !keep[p] {
			gone = append(gone, p)
		}
	}
	rows.Close()
	for _, p := range gone {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ports WHERE asset_id = ? AND host = ? AND port = ?`, assetID, host, p); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Cert is the latest TLS result for one endpoint.
type Cert struct {
	Host      string
	Port      int
	Subject   string
	Issuer    string
	NotAfter  *time.Time
	Version   string
	Problem   string
	CheckedAt time.Time
}

// PutCert stores a TLS result.
func (s *Store) PutCert(ctx context.Context, assetID int64, c Cert) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO certs (asset_id, host, port, subject, issuer, not_after, version, problem, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (asset_id, host, port) DO UPDATE SET subject = excluded.subject, issuer = excluded.issuer,
		 not_after = excluded.not_after, version = excluded.version, problem = excluded.problem, checked_at = excluded.checked_at`,
		assetID, c.Host, c.Port, c.Subject, c.Issuer, c.NotAfter, c.Version, c.Problem, time.Now().UTC())
	return err
}

// Certs returns TLS results for an asset.
func (s *Store) Certs(ctx context.Context, assetID int64) ([]Cert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, port, subject, issuer, not_after, version, problem, checked_at FROM certs WHERE asset_id = ? ORDER BY host, port`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		var c Cert
		var na sql.NullTime
		if err := rows.Scan(&c.Host, &c.Port, &c.Subject, &c.Issuer, &na, &c.Version, &c.Problem, &c.CheckedAt); err != nil {
			return nil, err
		}
		if na.Valid {
			t := na.Time
			c.NotAfter = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DNS returns the stored DNS records for an asset.
func (s *Store) DNS(ctx context.Context, assetID int64) ([]string, error) {
	return s.strings(ctx, `SELECT record FROM dns WHERE asset_id = ? ORDER BY record`, assetID)
}

// ReplaceDNS stores a new DNS snapshot.
func (s *Store) ReplaceDNS(ctx context.Context, assetID int64, records []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns WHERE asset_id = ?`, assetID); err != nil {
		return err
	}
	for _, r := range records {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO dns (asset_id, record) VALUES (?, ?)`, assetID, r); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Subdomains returns the known subdomains of an asset.
func (s *Store) Subdomains(ctx context.Context, assetID int64) ([]string, error) {
	return s.strings(ctx, `SELECT name FROM subdomains WHERE asset_id = ? ORDER BY name`, assetID)
}

// AddSubdomains stores names and returns the ones that were new.
func (s *Store) AddSubdomains(ctx context.Context, assetID int64, names []string) ([]string, error) {
	var added []string
	now := time.Now().UTC()
	for _, n := range names {
		res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO subdomains (asset_id, name, first_seen) VALUES (?, ?, ?)`, assetID, n, now)
		if err != nil {
			return added, err
		}
		if c, _ := res.RowsAffected(); c > 0 {
			added = append(added, n)
		}
	}
	return added, nil
}

func (s *Store) strings(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// AllPorts returns every open port, keyed by asset.
func (s *Store) AllPorts(ctx context.Context) (map[int64][]Port, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT asset_id, host, port, banner, first_seen, last_seen FROM ports ORDER BY asset_id, host, port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]Port{}
	for rows.Next() {
		var id int64
		var p Port
		if err := rows.Scan(&id, &p.Host, &p.Port, &p.Banner, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		out[id] = append(out[id], p)
	}
	return out, rows.Err()
}

// AssetCert is a certificate with the asset it belongs to.
type AssetCert struct {
	Cert
	AssetID int64
	Asset   string
}

// AllCerts returns every stored certificate result.
func (s *Store) AllCerts(ctx context.Context) ([]AssetCert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.asset_id, a.value, c.host, c.port, c.subject, c.issuer, c.not_after, c.version, c.problem, c.checked_at
		FROM certs c JOIN assets a ON a.id = c.asset_id ORDER BY c.not_after`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AssetCert
	for rows.Next() {
		var c AssetCert
		var na sql.NullTime
		if err := rows.Scan(&c.AssetID, &c.Asset, &c.Host, &c.Port, &c.Subject, &c.Issuer, &na, &c.Version, &c.Problem, &c.CheckedAt); err != nil {
			return nil, err
		}
		if na.Valid {
			t := na.Time
			c.NotAfter = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SubdomainCounts returns how many subdomains are known in total and how many appeared since t.
func (s *Store) SubdomainCounts(ctx context.Context, since time.Time) (total, recent int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(first_seen >= ?), 0) FROM subdomains`, since).Scan(&total, &recent)
	return
}

// LatestRun returns the most recent time any check ran.
func (s *Store) LatestRun(ctx context.Context) time.Time {
	// ORDER BY keeps the column's declared type; MAX() would return text the driver can't scan as a time.
	var t time.Time
	s.db.QueryRowContext(ctx, `SELECT ran_at FROM runs ORDER BY ran_at DESC LIMIT 1`).Scan(&t)
	return t
}

// Runs returns when each check last ran for an asset, with its error.
func (s *Store) Runs(ctx context.Context, assetID int64) (map[string]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT check_name, ran_at, error FROM runs WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Run{}
	for rows.Next() {
		var name string
		var r Run
		if err := rows.Scan(&name, &r.At, &r.Error); err != nil {
			return nil, err
		}
		out[name] = r
	}
	return out, rows.Err()
}

// Run is one check's last run.
type Run struct {
	At    time.Time
	Error string
}

// Finding is an ongoing problem, identified by a stable key so it is reported once.
type Finding struct {
	AssetID   int64
	Asset     string
	Key       string
	Severity  Severity
	Title     string
	Detail    string
	FirstSeen time.Time
}

// SyncFindings replaces the findings with the given key prefix and returns what was added and resolved.
func (s *Store) SyncFindings(ctx context.Context, assetID int64, prefix string, current []Finding) (added, resolved []Finding, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT key, severity, title, detail, first_seen FROM findings WHERE asset_id = ? AND key LIKE ? || '%'`, assetID, prefix)
	if err != nil {
		return nil, nil, err
	}
	old := map[string]Finding{}
	for rows.Next() {
		f := Finding{AssetID: assetID}
		if err := rows.Scan(&f.Key, &f.Severity, &f.Title, &f.Detail, &f.FirstSeen); err != nil {
			rows.Close()
			return nil, nil, err
		}
		old[f.Key] = f
	}
	rows.Close()

	now := time.Now().UTC()
	seen := map[string]bool{}
	for _, f := range current {
		seen[f.Key] = true
		prev, existed := old[f.Key]
		if !existed {
			f.AssetID, f.FirstSeen = assetID, now
			added = append(added, f)
		} else if f.Severity > prev.Severity {
			// Getting worse (e.g. 30 days left → 7 days left) counts as new.
			added = append(added, f)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO findings (asset_id, key, severity, title, detail, first_seen) VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (asset_id, key) DO UPDATE SET severity = excluded.severity, title = excluded.title, detail = excluded.detail`,
			assetID, f.Key, f.Severity, f.Title, f.Detail, now); err != nil {
			return nil, nil, err
		}
	}
	for k, f := range old {
		if !seen[k] {
			resolved = append(resolved, f)
			if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE asset_id = ? AND key = ?`, assetID, k); err != nil {
				return nil, nil, err
			}
		}
	}
	return added, resolved, tx.Commit()
}

// Findings returns open findings, worst first. assetID 0 means all assets.
func (s *Store) Findings(ctx context.Context, assetID int64) ([]Finding, error) {
	q := `SELECT f.asset_id, a.value, f.key, f.severity, f.title, f.detail, f.first_seen FROM findings f JOIN assets a ON a.id = f.asset_id`
	var args []any
	if assetID != 0 {
		q += ` WHERE f.asset_id = ?`
		args = append(args, assetID)
	}
	q += ` ORDER BY f.severity DESC, f.first_seen DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.AssetID, &f.Asset, &f.Key, &f.Severity, &f.Title, &f.Detail, &f.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Event is something that happened, shown on the timeline.
type Event struct {
	ID        int64
	AssetID   int64
	Asset     string
	Severity  Severity
	Title     string
	Detail    string
	CreatedAt time.Time
}

// AddEvent records an event.
func (s *Store) AddEvent(ctx context.Context, e Event) (Event, error) {
	e.CreatedAt = time.Now().UTC()
	var asset any
	if e.AssetID != 0 {
		asset = e.AssetID
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO events (asset_id, severity, title, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
		asset, e.Severity, e.Title, e.Detail, e.CreatedAt)
	if err != nil {
		return e, err
	}
	e.ID, _ = res.LastInsertId()
	return e, nil
}

// Events returns recent events. assetID 0 means all assets.
func (s *Store) Events(ctx context.Context, assetID int64, limit int) ([]Event, error) {
	q := `SELECT e.id, COALESCE(e.asset_id, 0), COALESCE(a.value, ''), e.severity, e.title, e.detail, e.created_at
	      FROM events e LEFT JOIN assets a ON a.id = e.asset_id`
	var args []any
	if assetID != 0 {
		q += ` WHERE e.asset_id = ?`
		args = append(args, assetID)
	}
	q += ` ORDER BY e.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.AssetID, &e.Asset, &e.Severity, &e.Title, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
