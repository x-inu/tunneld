// Package logx provides redacted application logging. Secrets are removed
// before a line reaches stdout, journald, or SQLite.
package logx

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"tunneld/internal/config"
	"tunneld/internal/store"
)

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

var (
	flagSecretRe = regexp.MustCompile(`(?i)\b(password|passwd|secret|psk|pre-shared-key|token)\b(\s*[=:]\s*)([^\s"']+|"[^"]*"|'[^']*')`)
	authRe       = regexp.MustCompile(`(?i)\b(authorization:\s*(?:bearer|basic)\s+)\S+`)
)

type Logger struct {
	store   *store.Store
	secrets *config.SecretStore
	min     Level
	std     *log.Logger
}

func New(st *store.Store, secrets *config.SecretStore, minLevel string) *Logger {
	lvl := LevelInfo
	switch minLevel {
	case "debug":
		lvl = LevelDebug
	case "warn":
		lvl = LevelWarn
	case "error":
		lvl = LevelError
	}
	return &Logger{
		store:   st,
		secrets: secrets,
		min:     lvl,
		std:     log.New(log.Writer(), "", log.LstdFlags|log.LUTC),
	}
}

func (l *Logger) Redact(s string) string {
	// Replace exact known secret values first, longest first.
	for _, secret := range l.secrets.Snapshot() {
		if len(secret) >= 3 {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	s = flagSecretRe.ReplaceAllString(s, "$1$2[redacted]")
	s = authRe.ReplaceAllString(s, "$1[redacted]")
	return s
}

func (l *Logger) Debug(tunnel, format string, args ...any) {
	l.write(LevelDebug, tunnel, format, args...)
}
func (l *Logger) Info(tunnel, format string, args ...any) {
	l.write(LevelInfo, tunnel, format, args...)
}
func (l *Logger) Warn(tunnel, format string, args ...any) {
	l.write(LevelWarn, tunnel, format, args...)
}
func (l *Logger) Error(tunnel, format string, args ...any) {
	l.write(LevelError, tunnel, format, args...)
}

func (l *Logger) write(level Level, tunnel, format string, args ...any) {
	if levelRank(level) < levelRank(l.min) {
		return
	}
	msg := l.Redact(fmt.Sprintf(format, args...))
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	if len(msg) > 4000 {
		msg = msg[:4000] + "…"
	}
	prefix := string(level)
	if tunnel != "" {
		prefix += " [" + tunnel + "]"
	}
	l.std.Printf("%s %s", prefix, msg)
	if l.store != nil && level != LevelDebug {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		l.store.AddLog(ctx, tunnel, string(level), msg)
	}
}

func (l *Logger) Audit(ctx context.Context, actor, action, tunnel, detail, ip string) {
	detail = l.Redact(detail)
	if l.store != nil {
		_ = l.store.AddAudit(ctx, store.Audit{
			At:     time.Now().UTC(),
			Actor:  actor,
			Action: action,
			Tunnel: tunnel,
			Detail: detail,
			IP:     ip,
		})
	}
	l.Info(tunnel, "audit actor=%s action=%s ip=%s detail=%s", actor, action, ip, detail)
}

func levelRank(l Level) int {
	switch l {
	case LevelDebug:
		return 0
	case LevelInfo:
		return 1
	case LevelWarn:
		return 2
	case LevelError:
		return 3
	}
	return 1
}
