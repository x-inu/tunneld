// Package store persists rotation history, audit entries, logs, and runtime
// settings in SQLite.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Rotation struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	FromTunnel string    `json:"from_tunnel"`
	ToTunnel   string    `json:"to_tunnel"`
	Reason     string    `json:"reason"`
	OldIP      string    `json:"old_public_ip"`
	NewIP      string    `json:"new_public_ip"`
	Success    bool      `json:"success"`
	Detail     string    `json:"detail"`
}

type Audit struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Tunnel string    `json:"tunnel"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

type Log struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Tunnel  string    `json:"tunnel"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS rotations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at_ms INTEGER NOT NULL,
			from_tunnel TEXT NOT NULL,
			to_tunnel TEXT NOT NULL,
			reason TEXT NOT NULL,
			old_ip TEXT NOT NULL,
			new_ip TEXT NOT NULL,
			success INTEGER NOT NULL,
			detail TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rotations_at ON rotations(at_ms DESC)`,
		`CREATE TABLE IF NOT EXISTS audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at_ms INTEGER NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			tunnel TEXT NOT NULL,
			detail TEXT NOT NULL,
			ip TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at_ms DESC)`,
		`CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at_ms INTEGER NOT NULL,
			tunnel TEXT NOT NULL,
			level TEXT NOT NULL,
			message TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_at ON logs(at_ms DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_tunnel_at ON logs(tunnel, at_ms DESC)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate database: %w", err)
		}
	}
	return nil
}

func (s *Store) AddRotation(ctx context.Context, r Rotation) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO rotations
		(at_ms, from_tunnel, to_tunnel, reason, old_ip, new_ip, success, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.At.UnixMilli(), r.FromTunnel, r.ToTunnel, r.Reason, r.OldIP, r.NewIP, boolInt(r.Success), r.Detail)
	return err
}

func (s *Store) ListRotations(ctx context.Context, limit int) ([]Rotation, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at_ms, from_tunnel, to_tunnel, reason, old_ip, new_ip, success, detail
		FROM rotations ORDER BY at_ms DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rotation
	for rows.Next() {
		var r Rotation
		var ms int64
		var success int
		if err := rows.Scan(&r.ID, &ms, &r.FromTunnel, &r.ToTunnel, &r.Reason, &r.OldIP, &r.NewIP, &success, &r.Detail); err != nil {
			return nil, err
		}
		r.At = time.UnixMilli(ms).UTC()
		r.Success = success != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddAudit(ctx context.Context, a Audit) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (at_ms, actor, action, tunnel, detail, ip)
		VALUES (?, ?, ?, ?, ?, ?)`, a.At.UnixMilli(), a.Actor, a.Action, a.Tunnel, truncate(a.Detail, 1000), a.IP)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]Audit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at_ms, actor, action, tunnel, detail, ip
		FROM audit ORDER BY at_ms DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Audit
	for rows.Next() {
		var a Audit
		var ms int64
		if err := rows.Scan(&a.ID, &ms, &a.Actor, &a.Action, &a.Tunnel, &a.Detail, &a.IP); err != nil {
			return nil, err
		}
		a.At = time.UnixMilli(ms).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AddLog(ctx context.Context, tunnel, level, message string) {
	_, _ = s.db.ExecContext(ctx, `INSERT INTO logs (at_ms, tunnel, level, message)
		VALUES (?, ?, ?, ?)`, time.Now().UTC().UnixMilli(), tunnel, level, truncate(message, 4000))
}

func (s *Store) ListLogs(ctx context.Context, tunnel string, limit int) ([]Log, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows *sql.Rows
	var err error
	if tunnel == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT id, at_ms, tunnel, level, message
			FROM logs ORDER BY at_ms DESC, id DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, at_ms, tunnel, level, message
			FROM logs WHERE tunnel = ? ORDER BY at_ms DESC, id DESC LIMIT ?`, tunnel, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Log
	for rows.Next() {
		var l Log
		var ms int64
		if err := rows.Scan(&l.ID, &ms, &l.Tunnel, &l.Level, &l.Message); err != nil {
			return nil, err
		}
		l.At = time.UnixMilli(ms).UTC()
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) GetIntSetting(ctx context.Context, key string, fallback int) int {
	v, ok, err := s.GetSetting(ctx, key)
	if err != nil || !ok {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func (s *Store) Prune(ctx context.Context, olderThan time.Time) error {
	cutoff := olderThan.UnixMilli()
	for _, q := range []string{
		`DELETE FROM logs WHERE at_ms < ?`,
		`DELETE FROM rotations WHERE at_ms < ?`,
		`DELETE FROM audit WHERE at_ms < ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, cutoff); err != nil {
			return err
		}
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
