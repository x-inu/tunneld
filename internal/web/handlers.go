package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tunneld/internal/config"
	"tunneld/internal/store"
)

const (
	loginBodyLimit  = 16 << 10
	tunnelBodyLimit = 32 << 10
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req, loginBodyLimit); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	sess, cookie, err := s.auth.Login(r, req.Username, req.Password)
	if err != nil {
		var rate *rateError
		if errors.As(err, &rate) {
			w.Header().Set("Retry-After", strconv.Itoa(rate.RetryAfter))
			s.audit(r, nil, "login.rate_limited", "", "too many failed login attempts")
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed attempts; try again in %d seconds", rate.RetryAfter))
			return
		}
		s.audit(r, nil, "login.failed", "", "invalid credentials")
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	http.SetCookie(w, cookie)
	s.audit(r, sess, "login", "", "administrator session created")
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   sess.Username,
		"csrf_token": sess.CSRF,
		"expires_in": s.cfg.Session.TTLHours * 3600,
		"demo":       s.cfg.Demo,
		"version":    s.version,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *session) {
	s.audit(r, sess, "logout", "", "administrator session ended")
	http.SetCookie(w, s.auth.Logout(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   sess.Username,
		"csrf_token": sess.CSRF,
		"expires_in": s.cfg.Session.TTLHours * 3600,
		"demo":       s.cfg.Demo,
		"version":    s.version,
	})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request, _ *session) {
	writeJSON(w, http.StatusOK, s.manager.Snapshot())
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request, _ *session) {
	limit := queryLimit(r, 50, 500)
	rows, err := s.store.ListRotations(r.Context(), limit)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, errors.New("could not read rotation history"))
		return
	}
	if rows == nil {
		rows = []store.Rotation{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request, _ *session) {
	limit := queryLimit(r, 200, 1000)
	rows, err := s.store.ListLogs(r.Context(), strings.TrimSpace(r.URL.Query().Get("tunnel")), limit)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, errors.New("could not read logs"))
		return
	}
	if rows == nil {
		rows = []store.Log{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ *session) {
	limit := queryLimit(r, 100, 500)
	rows, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, errors.New("could not read the audit trail"))
		return
	}
	if rows == nil {
		rows = []store.Audit{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func queryLimit(r *http.Request, fallback, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return fallback
	}
	if n > max {
		return max
	}
	return n
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	if err := s.manager.RotateNow(ctx); err != nil {
		s.audit(r, sess, "rotate.failed", "", s.log.Redact(err.Error()))
		s.fail(w, http.StatusConflict, err)
		return
	}
	s.audit(r, sess, "rotate", "", "manual rotation completed with a verified public IP")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRotation(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Mode            string `json:"mode"`
		IntervalMinutes *int   `json:"interval_minutes"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	current := s.manager.Snapshot().Rotation
	interval := current.IntervalMinutes
	if req.IntervalMinutes != nil {
		interval = *req.IntervalMinutes
	}
	if err := s.manager.SetRotation(strings.TrimSpace(req.Mode), interval); err != nil {
		s.audit(r, sess, "rotation.settings.failed", "", s.log.Redact(err.Error()))
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	s.audit(r, sess, "rotation.settings", "", fmt.Sprintf("mode=%s interval_minutes=%d", req.Mode, interval))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAddTunnel(w http.ResponseWriter, r *http.Request, sess *session) {
	var req tunnelRequest
	if err := decodeJSON(w, r, &req, tunnelBodyLimit); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	t, password, psk, err := buildTunnel(req, nil, "")
	if err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(password) == "" {
		writeError(w, http.StatusBadRequest, "a password is required when adding a tunnel")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.manager.AddTunnel(ctx, t, &password, psk); err != nil {
		s.audit(r, sess, "tunnel.add.failed", t.Name, s.log.Redact(err.Error()))
		s.fail(w, http.StatusConflict, err)
		return
	}
	s.audit(r, sess, "tunnel.add", t.Name, fmt.Sprintf("method=%s server=%s", t.Method, t.Server))
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) handleUpdateTunnel(w http.ResponseWriter, r *http.Request, sess *session) {
	name := strings.TrimSpace(r.PathValue("name"))
	old, ok := s.manager.Tunnel(name)
	if !ok {
		writeError(w, http.StatusNotFound, "tunnel not found")
		return
	}
	var req tunnelRequest
	if err := decodeJSON(w, r, &req, tunnelBodyLimit); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	t, password, psk, err := buildTunnel(req, &old, name)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	if t.Method == config.MethodL2TP && t.UseIPSec && !s.manager.HasPSK(t) && (psk == nil || strings.TrimSpace(*psk) == "") {
		writeError(w, http.StatusBadRequest, "an IPsec pre-shared key is required when use_ipsec is true")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.manager.UpdateTunnel(ctx, name, t, &password, psk); err != nil {
		s.audit(r, sess, "tunnel.update.failed", name, s.log.Redact(err.Error()))
		s.fail(w, http.StatusConflict, err)
		return
	}
	s.audit(r, sess, "tunnel.update", name, fmt.Sprintf("method=%s server=%s enabled=%t", t.Method, t.Server, t.Enabled))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request, sess *session) {
	name := strings.TrimSpace(r.PathValue("name"))
	if _, ok := s.manager.Tunnel(name); !ok {
		writeError(w, http.StatusNotFound, "tunnel not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.manager.DeleteTunnel(ctx, name); err != nil {
		s.audit(r, sess, "tunnel.delete.failed", name, s.log.Redact(err.Error()))
		s.fail(w, http.StatusConflict, err)
		return
	}
	s.audit(r, sess, "tunnel.delete", name, "tunnel definition and generated system configuration removed")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request, sess *session) {
	name := strings.TrimSpace(r.PathValue("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	if err := s.manager.Connect(ctx, name); err != nil {
		s.audit(r, sess, "tunnel.connect.failed", name, s.log.Redact(err.Error()))
		s.fail(w, http.StatusConflict, err)
		return
	}
	s.audit(r, sess, "tunnel.connect", name, "tunnel connected")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request, sess *session) {
	name := strings.TrimSpace(r.PathValue("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.manager.Disconnect(ctx, name); err != nil {
		s.audit(r, sess, "tunnel.disconnect.failed", name, s.log.Redact(err.Error()))
		s.fail(w, http.StatusConflict, err)
		return
	}
	s.audit(r, sess, "tunnel.disconnect", name, "tunnel disconnected")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request, sess *session) {
	name := strings.TrimSpace(r.PathValue("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	if err := s.manager.SetActive(ctx, name); err != nil {
		s.audit(r, sess, "tunnel.activate.failed", name, s.log.Redact(err.Error()))
		s.fail(w, http.StatusConflict, err)
		return
	}
	s.audit(r, sess, "tunnel.activate", name, "default route switched to tunnel and verified")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// tunnelRequest is the dashboard's editable tunnel surface. It never contains
// credential references; those are generated server-side.
type tunnelRequest struct {
	Name           string `json:"name"`
	Method         string `json:"method"`
	Server         string `json:"server"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	UseIPSec       bool   `json:"use_ipsec"`
	PSK            string `json:"psk"`
	SSTPPort       int    `json:"sstp_port"`
	SSTPIgnoreCert bool   `json:"sstp_ignore_cert"`
	SSTPCACert     string `json:"sstp_ca_cert"`
	PPTPPhone      string `json:"pptp_phone"`
	MTU            int    `json:"mtu"`
	MRU            int    `json:"mru"`
	RequireMPPE    bool   `json:"require_mppe"`
	Enabled        *bool  `json:"enabled"`
}

// buildTunnel validates the editable fields and preserves immutable credential
// references from old when editing. It returns the password separately so the
// manager can distinguish "keep the stored secret" from "replace it".
func buildTunnel(req tunnelRequest, old *config.Tunnel, pathName string) (config.Tunnel, string, *string, error) {
	if pathName != "" && req.Name != "" && req.Name != pathName {
		return config.Tunnel{}, "", nil, errors.New("tunnel name cannot be changed; delete and recreate the tunnel instead")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = pathName
	}
	if name == "" {
		return config.Tunnel{}, "", nil, errors.New("name is required")
	}
	method := config.Method(strings.ToLower(strings.TrimSpace(req.Method)))
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	} else if old != nil {
		enabled = old.Enabled
	}
	t := config.Tunnel{
		Name:           name,
		Method:         method,
		Server:         strings.TrimSpace(req.Server),
		Username:       strings.TrimSpace(req.Username),
		SSTPIgnoreCert: req.SSTPIgnoreCert,
		SSTPCACert:     strings.TrimSpace(req.SSTPCACert),
		PPTPPhone:      strings.TrimSpace(req.PPTPPhone),
		MTU:            req.MTU,
		MRU:            req.MRU,
		RequireMPPE:    req.RequireMPPE,
		Enabled:        enabled,
	}
	switch method {
	case config.MethodL2TP:
		t.UseIPSec = req.UseIPSec
		if t.UseIPSec {
			t.IPSecSecretRef = name + "-psk"
		}
		t.RequireMPPE = false
	case config.MethodSSTP:
		t.SSTPPort = req.SSTPPort
		if t.SSTPPort == 0 {
			t.SSTPPort = 443
		}
		t.RequireMPPE = false
	case config.MethodPPTP:
		t.RequireMPPE = req.RequireMPPE
	default:
		return config.Tunnel{}, "", nil, errors.New("method must be one of l2tp, sstp, pptp")
	}
	if old != nil {
		t.PasswordRef = old.PasswordRef
		if method == config.MethodL2TP && t.UseIPSec {
			if old.Method == config.MethodL2TP && old.UseIPSec && old.IPSecSecretRef != "" {
				t.IPSecSecretRef = old.IPSecSecretRef
			}
		}
	}
	if t.PasswordRef == "" {
		t.PasswordRef = name + "-password"
	}
	config.NormalizeTunnel(&t)
	if err := config.ValidateTunnel(&t, 0); err != nil {
		return config.Tunnel{}, "", nil, err
	}

	// Only return a PSK pointer when the protocol uses one. This also keeps a
	// stray PSK field from being stored for L2TP-without-IPsec.
	var psk *string
	if t.Method == config.MethodL2TP && t.UseIPSec && req.PSK != "" {
		v := req.PSK
		psk = &v
	}
	return t, req.Password, psk, nil
}
