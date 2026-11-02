// Package web serves the authenticated dashboard, JSON API, and SSE stream.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tunneld/internal/config"
)

const sessionCookie = "tunneld_session"

type session struct {
	ID       string
	Username string
	CSRF     string
	Created  time.Time
	LastSeen time.Time
}

type loginEntry struct {
	failures    []time.Time
	blockedTill time.Time
}

type Auth struct {
	cfg      *config.Config
	mu       sync.Mutex
	sessions map[string]*session
	logins   map[string]*loginEntry
}

func NewAuth(cfg *config.Config) *Auth {
	return &Auth{cfg: cfg, sessions: map[string]*session{}, logins: map[string]*loginEntry{}}
}

// HashPassword produces a bcrypt hash for the config file.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(h), err
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ClientIP returns the address used for auditing and login rate limiting.
func (a *Auth) ClientIP(r *http.Request) string { return clientIP(a.cfg, r) }

func (a *Auth) cookieName() string {
	if a.cfg.Session.CookieName != "" {
		return a.cfg.Session.CookieName
	}
	return sessionCookie
}

func cookieSecure(cfg *config.Config, r *http.Request) bool {
	switch cfg.Session.SecureOverride {
	case "true":
		return true
	case "false":
		return false
	}
	if r.TLS != nil {
		return true
	}
	if cfg.TrustProxy && isLoopbackRemote(r.RemoteAddr) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

func isLoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func clientIP(cfg *config.Config, r *http.Request) string {
	if cfg.TrustProxy && isLoopbackRemote(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Login verifies credentials and creates a server-side session. The caller
// must set the returned cookie.
func (a *Auth) Login(r *http.Request, username, password string) (*session, *http.Cookie, error) {
	ip := clientIP(a.cfg, r)
	now := time.Now()
	a.mu.Lock()
	entry := a.logins[ip]
	if entry == nil {
		entry = &loginEntry{}
		a.logins[ip] = entry
	}
	if entry.blockedTill.After(now) {
		retry := int(entry.blockedTill.Sub(now).Seconds()) + 1
		a.mu.Unlock()
		return nil, nil, &rateError{RetryAfter: retry}
	}
	// Keep a 15 minute sliding window, maximum 5 failures.
	cutoff := now.Add(-15 * time.Minute)
	kept := entry.failures[:0]
	for _, t := range entry.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	entry.failures = kept
	if len(entry.failures) >= 5 {
		entry.blockedTill = now.Add(15 * time.Minute)
		a.mu.Unlock()
		return nil, nil, &rateError{RetryAfter: 900}
	}
	a.mu.Unlock()

	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.Admin.Username)) == 1
	passErr := bcrypt.CompareHashAndPassword([]byte(a.cfg.Admin.PasswordHash), []byte(password))
	if !userOK || passErr != nil {
		a.mu.Lock()
		entry.failures = append(entry.failures, now)
		if len(entry.failures) >= 5 {
			entry.blockedTill = now.Add(15 * time.Minute)
		}
		a.mu.Unlock()
		return nil, nil, fmt.Errorf("invalid username or password")
	}

	id, err := randomToken()
	if err != nil {
		return nil, nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, nil, err
	}
	s := &session{ID: id, Username: username, CSRF: csrf, Created: now, LastSeen: now}
	a.mu.Lock()
	a.sessions[id] = s
	delete(a.logins, ip)
	a.mu.Unlock()

	cookie := &http.Cookie{
		Name:     a.cookieName(),
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   cookieSecure(a.cfg, r),
		MaxAge:   a.cfg.Session.TTLHours * 3600,
	}
	return s, cookie, nil
}

type rateError struct{ RetryAfter int }

func (e *rateError) Error() string { return "too many failed login attempts" }

// Authenticate returns the live session for a request.
func (a *Auth) Authenticate(r *http.Request) (*session, bool) {
	c, err := r.Cookie(a.cookieName())
	if err != nil || c.Value == "" {
		return nil, false
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok {
		return nil, false
	}
	ttl := time.Duration(a.cfg.Session.TTLHours) * time.Hour
	idle := time.Duration(a.cfg.Session.IdleMinutes) * time.Minute
	if now.Sub(s.Created) > ttl || now.Sub(s.LastSeen) > idle {
		delete(a.sessions, c.Value)
		return nil, false
	}
	s.LastSeen = now
	cp := *s
	return &cp, true
}

func (a *Auth) Logout(r *http.Request) *http.Cookie {
	c, err := r.Cookie(a.cookieName())
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	return &http.Cookie{
		Name:     a.cookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   cookieSecure(a.cfg, r),
		MaxAge:   -1,
	}
}

func (a *Auth) ValidCSRF(s *session, token string) bool {
	if s == nil || token == "" || len(token) != len(s.CSRF) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRF)) == 1
}

func (a *Auth) Cleanup(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			a.mu.Lock()
			ttl := time.Duration(a.cfg.Session.TTLHours) * time.Hour
			idle := time.Duration(a.cfg.Session.IdleMinutes) * time.Minute
			for id, s := range a.sessions {
				if now.Sub(s.Created) > ttl || now.Sub(s.LastSeen) > idle {
					delete(a.sessions, id)
				}
			}
			for ip, e := range a.logins {
				if e.blockedTill.Before(now.Add(-time.Hour)) && len(e.failures) == 0 {
					delete(a.logins, ip)
				}
			}
			a.mu.Unlock()
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
