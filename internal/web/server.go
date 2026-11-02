package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"tunneld/internal/config"
	"tunneld/internal/logx"
	"tunneld/internal/store"
	"tunneld/internal/tunnel"
)

//go:embed assets
var embeddedAssets embed.FS

// Server serves the dashboard, its JSON API, and the live event stream.
type Server struct {
	cfg     *config.Config
	manager *tunnel.Manager
	auth    *Auth
	store   *store.Store
	log     *logx.Logger
	version string

	index  []byte
	login  []byte
	static http.Handler
}

func NewServer(cfg *config.Config, manager *tunnel.Manager, auth *Auth, st *store.Store, logger *logx.Logger, version string) (*Server, error) {
	assets, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded index: %w", err)
	}
	login, err := fs.ReadFile(assets, "login.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded login page: %w", err)
	}
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:     cfg,
		manager: manager,
		auth:    auth,
		store:   st,
		log:     logger,
		version: version,
		index:   index,
		login:   login,
		static:  http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))),
	}, nil
}

// Handler builds the complete route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.withMutation(s.handleLogout))
	mux.HandleFunc("GET /api/session", s.withSession(s.handleSession))
	mux.HandleFunc("GET /api/state", s.withSession(s.handleState))
	mux.HandleFunc("GET /api/events", s.withSession(s.handleEvents))

	mux.HandleFunc("GET /api/history", s.withSession(s.handleHistory))
	mux.HandleFunc("GET /api/logs", s.withSession(s.handleLogs))
	mux.HandleFunc("GET /api/audit", s.withSession(s.handleAudit))

	mux.HandleFunc("POST /api/rotate", s.withMutation(s.handleRotate))
	mux.HandleFunc("POST /api/rotation", s.withMutation(s.handleRotation))
	mux.HandleFunc("POST /api/tunnels", s.withMutation(s.handleAddTunnel))
	mux.HandleFunc("PUT /api/tunnels/{name}", s.withMutation(s.handleUpdateTunnel))
	mux.HandleFunc("DELETE /api/tunnels/{name}", s.withMutation(s.handleDeleteTunnel))
	mux.HandleFunc("POST /api/tunnels/{name}/connect", s.withMutation(s.handleConnect))
	mux.HandleFunc("POST /api/tunnels/{name}/disconnect", s.withMutation(s.handleDisconnect))
	mux.HandleFunc("POST /api/tunnels/{name}/activate", s.withMutation(s.handleActivate))

	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /", s.handleIndex)

	return s.securityHeaders(s.recoverer(mux))
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "..") {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".woff2") {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.static.ServeHTTP(w, r)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.auth.Authenticate(r); !ok {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.serveHTML(w, s.index)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth.Authenticate(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.serveHTML(w, s.login)
}

func (s *Server) serveHTML(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *Server) withSession(h func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.auth.Authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) withMutation(h func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, sess *session) {
		if !s.auth.ValidCSRF(sess, r.Header.Get("X-CSRF-Token")) {
			writeError(w, http.StatusForbidden, "invalid or missing CSRF token")
			return
		}
		h(w, r, sess)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.TLS != nil || (s.cfg.TrustProxy && isLoopbackRemote(r.RemoteAddr) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("", "panic serving %s %s: %v", r.Method, path.Clean(r.URL.Path), rec)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		media := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
		if media != "application/json" {
			return errors.New("Content-Type must be application/json")
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("request body is too large")
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}
func (s *Server) fail(w http.ResponseWriter, status int, err error) {
	msg := "request failed"
	if err != nil {
		msg = s.log.Redact(err.Error())
	}
	writeError(w, status, msg)
}

func (s *Server) audit(r *http.Request, sess *session, action, tunnelName, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actor := "unknown"
	if sess != nil && sess.Username != "" {
		actor = sess.Username
	}
	s.log.Audit(ctx, actor, action, tunnelName, detail, s.auth.ClientIP(r))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, _ *session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-transform")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	send := func() bool {
		data, err := json.Marshal(s.manager.Snapshot())
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: state\ndata: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !send() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
