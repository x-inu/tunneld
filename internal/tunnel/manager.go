package tunnel

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"tunneld/internal/config"
	"tunneld/internal/logx"
	"tunneld/internal/store"
)

const (
	settingRotationMode     = "rotation_mode"
	settingRotationInterval = "rotation_interval_minutes"
	settingLastActive       = "last_active"
	settingPreviousIP       = "previous_public_ip"
	settingLastRotation     = "last_rotation_at"
	settingLastReason       = "last_rotation_reason"
)

type runtimeState struct {
	cfg            config.Tunnel
	status         Status
	link           Link
	publicIP       string
	latencyMS      int64
	lastCheck      time.Time
	lastError      string
	healthOK       bool
	failureStreak  int
	cooldownUntil  time.Time
	activeSince    time.Time
	connectStarted time.Time
}

type Manager struct {
	cfg     *config.Config
	store   *store.Store
	secrets *config.SecretStore
	log     *logx.Logger
	ops     Ops
	version string
	started time.Time
	demo    bool

	mu           sync.RWMutex
	opMu         sync.Mutex
	states       map[string]*runtimeState
	order        []string
	active       string
	currentIP    string
	directIP     string
	directCheck  time.Time
	previousIP   string
	lastRotation time.Time
	lastReason   string

	rotationMode     string
	rotationInterval int
	nextRotation     time.Time
	rotationRunning  bool
	timerRunning     bool
	failoverRunning  bool
	lastActiveWanted string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed bool
}

// New builds a manager using the real Linux operations backend, or the
// clearly-marked demo backend when demo mode is enabled.
func New(cfg *config.Config, tunnels []config.Tunnel, st *store.Store, secrets *config.SecretStore, logger *logx.Logger, version string) *Manager {
	var ops Ops
	if cfg.Demo {
		ops = NewDemoOps()
	} else {
		ops = NewLinuxOps(cfg, secrets, logger)
	}
	return NewWithOps(cfg, tunnels, st, secrets, logger, version, ops)
}

// NewWithOps allows tests to inject a fake system boundary.
func NewWithOps(cfg *config.Config, tunnels []config.Tunnel, st *store.Store, secrets *config.SecretStore, logger *logx.Logger, version string, ops Ops) *Manager {
	m := &Manager{
		cfg:              cfg,
		store:            st,
		secrets:          secrets,
		log:              logger,
		ops:              ops,
		version:          version,
		started:          time.Now().UTC(),
		demo:             cfg.Demo,
		states:           make(map[string]*runtimeState, len(tunnels)),
		rotationMode:     cfg.Rotation.DefaultMode,
		rotationInterval: cfg.Rotation.DefaultIntervalMinutes,
	}
	for _, t := range tunnels {
		m.addStateLocked(t)
	}
	return m
}

func (m *Manager) addStateLocked(t config.Tunnel) {
	if _, exists := m.states[t.Name]; !exists {
		m.order = append(m.order, t.Name)
	}
	m.states[t.Name] = &runtimeState{cfg: t, status: StatusDisconnected}
}

func (m *Manager) loadSettings() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if v, ok, _ := m.store.GetSetting(ctx, settingRotationMode); ok {
		switch v {
		case "manual", "timer", "failover":
			m.rotationMode = v
		}
	}
	if v, ok, _ := m.store.GetSetting(ctx, settingRotationInterval); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= m.cfg.Rotation.MinIntervalMinutes && n <= m.cfg.Rotation.MaxIntervalMinutes {
			m.rotationInterval = n
		}
	}
	if v, ok, _ := m.store.GetSetting(ctx, settingLastActive); ok {
		m.lastActiveWanted = v
	}
	if v, ok, _ := m.store.GetSetting(ctx, settingPreviousIP); ok {
		m.previousIP = v
	}
	if v, ok, _ := m.store.GetSetting(ctx, settingLastReason); ok {
		m.lastReason = v
	}
	if v, ok, _ := m.store.GetSetting(ctx, settingLastRotation); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			m.lastRotation = t
		}
	}
}

// Start begins health, timer, and restore loops and returns immediately.
func (m *Manager) Start(parent context.Context) error {
	m.mu.Lock()
	if m.ctx != nil {
		m.mu.Unlock()
		return errors.New("manager already started")
	}
	m.ctx, m.cancel = context.WithCancel(parent)
	ctx := m.ctx
	m.mu.Unlock()

	m.loadSettings()
	m.mu.Lock()
	if m.rotationMode == "timer" {
		base := m.lastRotation
		if base.IsZero() {
			base = time.Now().UTC()
		}
		next := base.Add(time.Duration(m.rotationInterval) * time.Minute)
		if next.Before(time.Now().UTC().Add(2 * time.Second)) {
			next = time.Now().UTC().Add(5 * time.Second)
		}
		m.nextRotation = next
	}
	m.mu.Unlock()

	initCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	if err := m.ops.Init(initCtx, m.tunnelList()); err != nil {
		m.log.Warn("", "system initialization incomplete: %v", err)
	}
	cancel()

	m.wg.Add(3)
	go m.healthLoop()
	go m.timerLoop()
	go m.restoreLoop()
	go m.refreshDirectIP(ctx)
	m.log.Info("", "tunneld %s started in %s mode with %d tunnel definitions", m.version, m.rotationMode, len(m.order))
	return nil
}

func (m *Manager) tunnelList() []config.Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]config.Tunnel, 0, len(m.order))
	for _, name := range m.order {
		if st, ok := m.states[name]; ok {
			out = append(out, st.cfg)
		}
	}
	return out
}

func (m *Manager) tunnelConfig(name string) (config.Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st, ok := m.states[name]
	if !ok {
		return config.Tunnel{}, false
	}
	return st.cfg, true
}

// Snapshot returns a consistent, secret-free view for the dashboard.
func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now().UTC()
	s := Snapshot{
		Now:              now,
		Version:          m.version,
		Demo:             m.demo,
		Active:           m.active,
		PublicIP:         m.currentIP,
		DirectIP:         m.directIP,
		PreviousPublicIP: m.previousIP,
		UptimeSeconds:    int64(now.Sub(m.started).Seconds()),
	}
	if !m.directCheck.IsZero() {
		t := m.directCheck
		s.DirectCheck = &t
	}
	if m.active == "" && m.directIP != "" {
		s.PublicIP = m.directIP
	}
	if !m.lastRotation.IsZero() {
		t := m.lastRotation
		s.LastRotationAt = &t
	}
	mode := m.rotationMode
	if mode == "" {
		mode = "manual"
	}
	rv := RotationView{
		Mode:            mode,
		IntervalMinutes: m.rotationInterval,
		Running:         m.rotationRunning,
		LastReason:      m.lastReason,
		MinInterval:     m.cfg.Rotation.MinIntervalMinutes,
		MaxInterval:     m.cfg.Rotation.MaxIntervalMinutes,
	}
	if mode == "timer" && !m.nextRotation.IsZero() {
		t := m.nextRotation
		rv.NextAt = &t
		secs := int(math.Ceil(t.Sub(now).Seconds()))
		if secs < 0 {
			secs = 0
		}
		rv.CountdownSeconds = secs
	}
	s.Rotation = rv

	for _, name := range m.order {
		st, ok := m.states[name]
		if !ok {
			continue
		}
		t := st.cfg
		v := TunnelView{
			Name:           t.Name,
			Method:         string(t.Method),
			Server:         t.Server,
			Username:       t.Username,
			Enabled:        t.Enabled,
			Status:         st.status,
			Iface:          st.link.Iface,
			LocalIP:        st.link.LocalIP,
			PeerIP:         st.link.PeerIP,
			PublicIP:       st.publicIP,
			LatencyMS:      st.latencyMS,
			LastError:      st.lastError,
			HealthOK:       st.healthOK,
			Active:         m.active == name,
			FailureStreak:  st.failureStreak,
			HasPassword:    m.secrets.Has(t.PasswordRef),
			HasPSK:         t.IPSecSecretRef != "" && m.secrets.Has(t.IPSecSecretRef),
			UseIPSec:       t.UseIPSec,
			SSTPPort:       t.SSTPPort,
			SSTPIgnoreCert: t.SSTPIgnoreCert,
			SSTPCACert:     t.SSTPCACert,
			PPTPPhone:      t.PPTPPhone,
			MTU:            t.MTU,
			MRU:            t.MRU,
			RequireMPPE:    t.RequireMPPE,
		}
		if st.status == StatusConnected || st.status == StatusFailed {
			if !st.link.Since.IsZero() {
				v.UptimeSeconds = int64(now.Sub(st.link.Since).Seconds())
				if v.UptimeSeconds < 0 {
					v.UptimeSeconds = 0
				}
			}
		}
		if !st.lastCheck.IsZero() {
			tm := st.lastCheck
			v.LastCheck = &tm
		}
		if m.active == name && !st.activeSince.IsZero() {
			tm := st.activeSince
			v.ActiveSince = &tm
		}
		if !st.cooldownUntil.IsZero() && st.cooldownUntil.After(now) {
			tm := st.cooldownUntil
			v.CooldownUntil = &tm
		}
		switch t.Method {
		case config.MethodPPTP:
			v.Warning = "PPTP is deprecated and its encryption is weak. Use only for legacy compatibility."
		case config.MethodSSTP:
			if t.SSTPIgnoreCert {
				v.Warning = "TLS certificate validation is disabled for this tunnel. Traffic is exposed to interception."
			}
		case config.MethodL2TP:
			if !t.UseIPSec {
				v.Warning = "L2TP without IPsec does not encrypt traffic."
			}
		}
		if v.Warning == "" && st.cooldownUntil.After(now) {
			v.Warning = "Temporarily excluded from rotation after repeated health failures."
		}
		s.Tunnels = append(s.Tunnels, v)
		s.Counts.Total++
		if st.status == StatusConnected {
			s.Counts.Connected++
		}
		if st.healthOK && st.status == StatusConnected && !st.cooldownUntil.After(now) {
			s.Counts.Healthy++
			if m.active != name {
				s.Counts.Standby++
			}
		}
		if st.status == StatusFailed {
			s.Counts.Failed++
		}
	}
	if st, ok := m.states[m.active]; ok && m.active != "" {
		s.ActiveMethod = string(st.cfg.Method)
		s.ActiveServer = st.cfg.Server
	}
	return s
}

func (m *Manager) runtime(name string) (*runtimeState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st, ok := m.states[name]
	if !ok || st == nil {
		return nil, false
	}
	cp := *st
	return &cp, true
}

func (m *Manager) safeErr(err error) string {
	if err == nil {
		return ""
	}
	return m.log.Redact(err.Error())
}

// Connect brings one tunnel up without changing the default route.
func (m *Manager) Connect(ctx context.Context, name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.connectLocked(ctx, name)
}

func (m *Manager) connectLocked(ctx context.Context, name string) error {
	m.mu.RLock()
	st, ok := m.states[name]
	var t config.Tunnel
	var status Status
	if ok {
		t = st.cfg
		status = st.status
	}
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("tunnel %q is not configured", name)
	}
	if !t.Enabled {
		return fmt.Errorf("tunnel %q is disabled", name)
	}
	if status == StatusConnected || status == StatusConnecting {
		return nil
	}
	if !m.secrets.Has(t.PasswordRef) && !m.demo {
		msg := "no password is stored for this tunnel; edit the tunnel and set one"
		m.mu.Lock()
		st.lastError = msg
		st.status = StatusFailed
		m.mu.Unlock()
		return errors.New(msg)
	}
	if t.Method == config.MethodL2TP && t.UseIPSec && !m.secrets.Has(t.IPSecSecretRef) && !m.demo {
		msg := "no IPsec pre-shared key is stored for this tunnel"
		m.mu.Lock()
		st.lastError = msg
		st.status = StatusFailed
		m.mu.Unlock()
		return errors.New(msg)
	}

	m.mu.Lock()
	st.status = StatusConnecting
	st.connectStarted = time.Now().UTC()
	st.lastError = ""
	m.mu.Unlock()
	m.log.Info(name, "connect requested (%s to %s)", t.Method, t.Server)

	link, err := m.ops.Connect(ctx, t)
	if err != nil {
		msg := m.safeErr(err)
		m.mu.Lock()
		st.status = StatusFailed
		st.lastError = msg
		st.healthOK = false
		m.mu.Unlock()
		m.log.Error(name, "connect failed: %s", msg)
		return fmt.Errorf("%s", msg)
	}

	now := time.Now().UTC()
	m.mu.Lock()
	st.status = StatusConnected
	st.link = link
	st.healthOK = false
	st.failureStreak = 0
	st.lastError = ""
	st.activeSince = time.Time{}
	if link.Since.IsZero() {
		st.link.Since = now
	}
	m.mu.Unlock()
	m.log.Info(name, "connected on %s, tunnel local %s, gateway %s", link.Iface, link.LocalIP, link.PeerIP)

	// First health check gives the card a public IP immediately. Failure keeps
	// the link connected but marks it unhealthy.
	timeout := m.cfg.Health.Timeout()
	hctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	pub, latency, herr := m.ops.Health(hctx, t, link, timeout)
	cancel()
	m.mu.Lock()
	if herr != nil {
		msg := m.safeErr(herr)
		st.healthOK = false
		st.failureStreak = 1
		st.lastCheck = time.Now().UTC()
		st.lastError = "Connected, but the first health check failed: " + msg
	} else {
		st.healthOK = true
		st.failureStreak = 0
		st.publicIP = pub
		st.latencyMS = latency.Milliseconds()
		st.lastCheck = time.Now().UTC()
		st.lastError = ""
	}
	m.mu.Unlock()
	if herr != nil {
		m.log.Warn(name, "connected but health check failed: %s", m.safeErr(herr))
	} else {
		m.log.Info(name, "health ok: public IP %s, latency %dms", pub, latency.Milliseconds())
	}
	return nil
}

// Disconnect tears one tunnel down. If it is active, the original uplink route
// is restored before the interface disappears.
func (m *Manager) Disconnect(ctx context.Context, name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.disconnectLocked(ctx, name)
}

func (m *Manager) disconnectLocked(ctx context.Context, name string) error {
	m.mu.RLock()
	st, ok := m.states[name]
	if !ok {
		m.mu.RUnlock()
		return fmt.Errorf("tunnel %q is not configured", name)
	}
	t := st.cfg
	status := st.status
	wasActive := m.active == name
	oldIP := st.publicIP
	m.mu.RUnlock()
	if wasActive {
		if err := m.ops.RestoreOriginal(ctx); err != nil {
			return fmt.Errorf("refusing to disconnect the active tunnel: could not restore the original uplink route: %w", err)
		}
		m.mu.Lock()
		m.active = ""
		m.currentIP = m.directIP
		m.previousIP = oldIP
		m.lastActiveWanted = ""
		m.mu.Unlock()
		m.persist(settingLastActive, "")
		m.persist(settingPreviousIP, oldIP)
		m.log.Warn(name, "active tunnel disconnected; traffic returned to the original uplink")
		go m.refreshDirectIP(context.Background())
	}
	if status == StatusDisconnected && st.link.Iface == "" {
		_ = m.ops.Cleanup(ctx, name)
		return nil
	}

	m.mu.Lock()
	st.status = StatusDisconnecting
	m.mu.Unlock()
	err := m.ops.Disconnect(ctx, t)
	_ = m.ops.Cleanup(ctx, name)
	m.mu.Lock()
	st.link = Link{}
	st.publicIP = ""
	st.latencyMS = 0
	st.healthOK = false
	st.failureStreak = 0
	st.lastCheck = time.Time{}
	st.cooldownUntil = time.Time{}
	if err != nil {
		st.status = StatusFailed
		st.lastError = "Disconnect failed: " + m.safeErr(err)
	} else {
		st.status = StatusDisconnected
		st.lastError = ""
	}
	m.mu.Unlock()
	if err != nil {
		m.log.Error(name, "disconnect failed: %s", m.safeErr(err))
		return fmt.Errorf("%s", m.safeErr(err))
	}
	m.log.Info(name, "disconnected")
	return nil
}

// SetActive explicitly activates a tunnel selected by the administrator.
func (m *Manager) SetActive(ctx context.Context, name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	from, oldIP, newIP, err := m.tryActivateLocked(ctx, name, false)
	if err != nil {
		return err
	}
	if from != name {
		m.recordRotation(ctx, from, name, "manual", oldIP, newIP, true, "selected from dashboard")
	}
	return nil
}

// RotateNow selects the next healthy tunnel and verifies the new public IP.
func (m *Manager) RotateNow(ctx context.Context) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.rotateLocked(ctx, "manual")
}

func (m *Manager) rotateLocked(ctx context.Context, reason string) error {
	m.mu.Lock()
	if m.rotationRunning {
		m.mu.Unlock()
		return errors.New("a rotation is already in progress")
	}
	m.rotationRunning = true
	active := m.active
	oldIP := m.currentIP
	healthy := m.countHealthyLocked()
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.rotationRunning = false
		m.mu.Unlock()
	}()

	if active == "" {
		m.mu.Lock()
		candidates := m.candidatesLocked("")
		m.mu.Unlock()
		if len(candidates) == 0 {
			detail := "no healthy tunnel is available"
			m.recordRotation(ctx, "", "", reason, oldIP, "", false, detail)
			return errors.New(detail)
		}
		from, oip, nip, err := m.tryActivateLocked(ctx, candidates[0], true)
		if err != nil {
			m.recordRotation(ctx, from, candidates[0], reason, oip, "", false, m.safeErr(err))
			return err
		}
		m.recordRotation(ctx, from, candidates[0], reason, oip, nip, true, "activated first healthy tunnel")
		return nil
	}

	if healthy < m.cfg.Rotation.MinHealthy {
		detail := fmt.Sprintf("rotation skipped: only %d healthy tunnel(s) available, minimum is %d", healthy, m.cfg.Rotation.MinHealthy)
		m.recordRotation(ctx, active, "", reason, oldIP, "", false, detail)
		return errors.New(detail)
	}

	m.mu.Lock()
	candidates := m.candidatesLocked(active)
	m.mu.Unlock()
	if len(candidates) == 0 {
		detail := "rotation skipped: no healthy standby tunnel is available"
		m.recordRotation(ctx, active, "", reason, oldIP, "", false, detail)
		return errors.New(detail)
	}

	var lastErr error
	for _, target := range candidates {
		from, oip, nip, err := m.tryActivateLocked(ctx, target, true)
		if err == nil {
			m.recordRotation(ctx, from, target, reason, oip, nip, true, "default route switched and public IP verified")
			return nil
		}
		lastErr = err
		m.log.Warn(target, "rotation candidate rejected: %s", m.safeErr(err))
	}
	detail := "all rotation candidates failed verification"
	if lastErr != nil {
		detail = m.safeErr(lastErr)
	}
	m.recordRotation(ctx, active, candidates[len(candidates)-1], reason, oldIP, "", false, detail)
	return fmt.Errorf("rotation failed: %s", detail)
}

// countHealthyLocked counts usable rotation candidates.
func (m *Manager) countHealthyLocked() int {
	now := time.Now().UTC()
	n := 0
	for _, name := range m.order {
		st := m.states[name]
		if st == nil || !st.cfg.Enabled || st.status != StatusConnected || !st.healthOK {
			continue
		}
		if !st.cooldownUntil.IsZero() && st.cooldownUntil.After(now) {
			continue
		}
		if !st.link.Since.IsZero() && now.Sub(st.link.Since) < 2*time.Second {
			// Allow fresh links; this condition is intentionally not limiting.
		}
		n++
	}
	return n
}

// candidatesLocked returns healthy non-active tunnels in rotation order,
// preferring a tunnel whose last known public IP differs from the current one.
func (m *Manager) candidatesLocked(active string) []string {
	now := time.Now().UTC()
	curIP := m.currentIP
	start := 0
	for i, n := range m.order {
		if n == active {
			start = i + 1
			break
		}
	}
	var differing, same []string
	for i := 0; i < len(m.order); i++ {
		name := m.order[(start+i)%len(m.order)]
		if name == active {
			continue
		}
		st := m.states[name]
		if st == nil || !st.cfg.Enabled || st.status != StatusConnected || !st.healthOK {
			continue
		}
		if !st.cooldownUntil.IsZero() && st.cooldownUntil.After(now) {
			continue
		}
		if curIP != "" && st.publicIP != "" && st.publicIP != curIP {
			differing = append(differing, name)
		} else {
			same = append(same, name)
		}
	}
	return append(differing, same...)
}

// tryActivateLocked is the single route-switch transaction: set default route,
// verify through the tunnel interface and through the default route, and roll
// back on any mismatch. It updates runtime state but does not write history.
func (m *Manager) tryActivateLocked(ctx context.Context, target string, strictDifferent bool) (from, oldIP, newIP string, err error) {
	m.mu.RLock()
	from = m.active
	oldIP = m.currentIP
	targetState, ok := m.states[target]
	var t config.Tunnel
	if ok {
		t = targetState.cfg
	}
	m.mu.RUnlock()
	if !ok {
		return from, oldIP, "", fmt.Errorf("tunnel %q is not configured", target)
	}
	if !t.Enabled {
		return from, oldIP, "", fmt.Errorf("tunnel %q is disabled", target)
	}
	if from == target {
		return from, oldIP, oldIP, nil
	}

	// Make sure the target is connected and freshly verified before switching.
	st, ok := m.runtime(target)
	if !ok || st == nil {
		return from, oldIP, "", fmt.Errorf("tunnel %q is not available", target)
	}
	if st.status != StatusConnected {
		return from, oldIP, "", fmt.Errorf("tunnel %q is not connected (status %s)", target, st.status)
	}
	if !st.healthOK || time.Since(st.lastCheck) > 2*m.cfg.Health.Interval() {
		hctx, cancel := context.WithTimeout(ctx, m.cfg.Health.Timeout()+5*time.Second)
		pub, latency, herr := m.ops.Health(hctx, t, st.link, m.cfg.Health.Timeout())
		cancel()
		if herr != nil {
			m.mu.Lock()
			if cur := m.states[target]; cur != nil {
				cur.healthOK = false
				cur.lastError = "Health check failed before activation: " + m.safeErr(herr)
			}
			m.mu.Unlock()
			return from, oldIP, "", fmt.Errorf("tunnel %q failed the pre-activation health check: %s", target, m.safeErr(herr))
		}
		m.mu.Lock()
		if cur := m.states[target]; cur != nil {
			cur.healthOK = true
			cur.publicIP = pub
			cur.latencyMS = latency.Milliseconds()
			cur.lastCheck = time.Now().UTC()
			cur.lastError = ""
		}
		m.mu.Unlock()
		st.publicIP = pub
	}

	prevRoute, err := m.ops.Activate(ctx, t, st.link)
	if err != nil {
		return from, oldIP, "", fmt.Errorf("could not switch the default route: %w", err)
	}

	rollback := func(reason string) (string, string, string, error) {
		if rbErr := m.ops.Restore(ctx, prevRoute); rbErr != nil {
			m.log.Error(target, "rollback to %s failed: %s", prevRoute.Dev, m.safeErr(rbErr))
			reason += "; rollback also failed: " + m.safeErr(rbErr)
		}
		m.mu.Lock()
		m.currentIP = oldIP
		m.mu.Unlock()
		return from, oldIP, "", errors.New(reason)
	}

	verifyTimeout := time.Duration(m.cfg.Rotation.VerifyTimeoutSeconds) * time.Second
	vctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	ifaceIP, _, herr := m.ops.Health(vctx, t, st.link, m.cfg.Health.Timeout())
	if herr != nil {
		return rollback(fmt.Sprintf("new route could not be verified through %s: %s", st.link.Iface, m.safeErr(herr)))
	}
	defaultIP, derr := m.ops.VerifyDefault(vctx)
	if derr != nil {
		return rollback(fmt.Sprintf("default route verification failed: %s", m.safeErr(derr)))
	}
	if net.ParseIP(ifaceIP) == nil {
		return rollback("public IP checker returned an invalid address through the new tunnel")
	}
	if defaultIP != "" && ifaceIP != "" && defaultIP != ifaceIP {
		return rollback(fmt.Sprintf("default route exits with %s but the tunnel interface reports %s", defaultIP, ifaceIP))
	}
	if strictDifferent && oldIP != "" && ifaceIP == oldIP {
		return rollback(fmt.Sprintf("public IP did not change (still %s)", ifaceIP))
	}

	now := time.Now().UTC()
	m.mu.Lock()
	m.active = target
	m.currentIP = ifaceIP
	if oldIP != "" {
		m.previousIP = oldIP
	}
	m.lastRotation = now
	m.lastActiveWanted = target
	if cur := m.states[target]; cur != nil {
		cur.activeSince = now
		cur.publicIP = ifaceIP
		cur.healthOK = true
		cur.lastCheck = now
		cur.lastError = ""
		cur.cooldownUntil = time.Time{}
	}
	m.mu.Unlock()
	m.persist(settingLastActive, target)
	m.persist(settingPreviousIP, m.previousIP)
	m.persist(settingLastRotation, now.Format(time.RFC3339))
	return from, oldIP, ifaceIP, nil
}

func (m *Manager) recordRotation(ctx context.Context, from, to, reason, oldIP, newIP string, success bool, detail string) {
	_ = ctx
	detail = m.log.Redact(detail)
	now := time.Now().UTC()
	m.mu.Lock()
	if success {
		m.lastRotation = now
		m.lastReason = reason
	}
	m.mu.Unlock()
	if success {
		m.persist(settingLastRotation, now.Format(time.RFC3339))
		m.persist(settingLastReason, reason)
	}
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.store.AddRotation(c, store.Rotation{
		At:         now,
		FromTunnel: from,
		ToTunnel:   to,
		Reason:     reason,
		OldIP:      oldIP,
		NewIP:      newIP,
		Success:    success,
		Detail:     detail,
	}); err != nil {
		m.log.Error("", "could not write rotation history: %v", err)
	}
	if success {
		m.log.Info(to, "rotation succeeded (%s): %s %s -> %s %s", reason, from, oldIP, to, newIP)
	} else {
		m.log.Warn(to, "rotation failed (%s): %s", reason, detail)
	}
}

// Failover is invoked after the active tunnel repeatedly fails health checks.
func (m *Manager) Failover(reason string) {
	m.mu.Lock()
	if m.failoverRunning {
		m.mu.Unlock()
		return
	}
	active := m.active
	if active == "" {
		m.mu.Unlock()
		return
	}
	st := m.states[active]
	if st == nil || st.healthOK {
		m.mu.Unlock()
		return
	}
	oldIP := m.currentIP
	if oldIP == "" {
		oldIP = st.publicIP
	}
	m.failoverRunning = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.failoverRunning = false
		m.mu.Unlock()
	}()

	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	if m.active != active {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	m.mu.Lock()
	candidates := m.candidatesLocked(active)
	m.mu.Unlock()
	if len(candidates) == 0 {
		detail := "active tunnel is unhealthy and no healthy standby tunnel is available; traffic returned to the original uplink"
		if err := m.ops.RestoreOriginal(context.Background()); err != nil {
			detail = "active tunnel is unhealthy and the original uplink route could not be restored: " + m.safeErr(err)
		}
		m.mu.Lock()
		m.active = ""
		m.currentIP = m.directIP
		m.previousIP = oldIP
		m.lastActiveWanted = ""
		m.mu.Unlock()
		m.persist(settingLastActive, "")
		m.persist(settingPreviousIP, oldIP)
		m.recordRotation(context.Background(), active, "", "failover", oldIP, "", false, detail)
		m.log.Error(active, "%s", detail)
		go m.refreshDirectIP(context.Background())
		return
	}
	var lastErr error
	for _, target := range candidates {
		from, oip, nip, err := m.tryActivateLocked(context.Background(), target, false)
		if err == nil {
			m.recordRotation(context.Background(), from, target, "failover", oip, nip, true, reason)
			m.log.Warn(active, "failover switched to %s: %s", target, reason)
			return
		}
		lastErr = err
		m.log.Warn(target, "failover candidate failed: %s", m.safeErr(err))
	}
	detail := "failover failed: every healthy candidate was rejected"
	if lastErr != nil {
		detail = "failover failed: " + m.safeErr(lastErr)
	}
	if err := m.ops.RestoreOriginal(context.Background()); err != nil {
		detail += "; original uplink restore failed: " + m.safeErr(err)
	}
	m.mu.Lock()
	m.active = ""
	m.currentIP = ""
	m.previousIP = oldIP
	m.lastActiveWanted = ""
	m.mu.Unlock()
	m.persist(settingLastActive, "")
	m.persist(settingPreviousIP, oldIP)
	m.recordRotation(context.Background(), active, "", "failover", oldIP, "", false, detail)
	m.log.Error(active, "%s", detail)
}

func (m *Manager) healthLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.Health.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.runHealthOnce()
			m.mu.RLock()
			active := m.active
			m.mu.RUnlock()
			if active == "" {
				go m.refreshDirectIP(m.ctx)
			}
		}
	}
}

func (m *Manager) refreshDirectIP(ctx context.Context) {
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ip, err := m.ops.VerifyDefault(c)
	if err == nil && ip != "" {
		m.mu.Lock()
		m.directIP = ip
		m.directCheck = time.Now().UTC()
		if m.active == "" {
			m.currentIP = ip
		}
		m.mu.Unlock()
	}
}

func (m *Manager) runHealthOnce() {
	m.mu.RLock()
	type job struct {
		name string
		t    config.Tunnel
		link Link
	}
	var jobs []job
	for _, name := range m.order {
		st := m.states[name]
		if st == nil || !st.cfg.Enabled || st.status != StatusConnected || st.link.Iface == "" {
			continue
		}
		jobs = append(jobs, job{name: name, t: st.cfg, link: st.link})
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, j := range jobs {
		j := j
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			m.checkOne(j.name, j.t, j.link)
		}()
	}
	wg.Wait()
}

func (m *Manager) checkOne(name string, t config.Tunnel, expected Link) {
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Health.Timeout()+5*time.Second)
	defer cancel()

	live, ok := m.ops.Link(ctx, name)
	if !ok || live.Iface == "" {
		m.handleLinkLost(name, expected)
		return
	}
	if expected.Iface != "" && live.Iface != expected.Iface {
		// Interface numbers can change; trust live state by name.
		m.mu.Lock()
		if st := m.states[name]; st != nil {
			st.link = live
		}
		m.mu.Unlock()
	}
	pub, latency, err := m.ops.Health(ctx, t, live, m.cfg.Health.Timeout())
	now := time.Now().UTC()
	m.mu.Lock()
	st := m.states[name]
	if st == nil || st.link.Iface != live.Iface {
		m.mu.Unlock()
		return
	}
	st.lastCheck = now
	if err != nil {
		st.healthOK = false
		st.failureStreak++
		msg := m.safeErr(err)
		st.lastError = "Health check failed: " + msg
		if st.failureStreak == m.cfg.Health.FailThreshold {
			st.cooldownUntil = now.Add(m.cfg.Health.Cooldown())
			m.log.Warn(name, "health failed %d times; temporarily excluded from rotation until it recovers (%s)", st.failureStreak, msg)
		} else {
			m.log.Warn(name, "health check failed (%d/%d): %s", st.failureStreak, m.cfg.Health.FailThreshold, msg)
		}
		active := m.active == name
		failed := st.failureStreak >= m.cfg.Health.FailThreshold
		m.mu.Unlock()
		if active && failed {
			go m.Failover(fmt.Sprintf("active tunnel failed %d consecutive health checks: %s", m.cfg.Health.FailThreshold, msg))
		}
		return
	}
	oldIP := st.publicIP
	st.healthOK = true
	st.failureStreak = 0
	st.cooldownUntil = time.Time{}
	st.latencyMS = latency.Milliseconds()
	st.lastCheck = now
	st.lastError = ""
	st.publicIP = pub
	active := m.active == name
	if active {
		m.currentIP = pub
	}
	m.mu.Unlock()

	if active && oldIP != "" && pub != "" && oldIP != pub {
		m.mu.Lock()
		m.previousIP = oldIP
		m.mu.Unlock()
		m.persist(settingPreviousIP, oldIP)
		m.log.Warn(name, "active public IP changed outside a rotation: %s -> %s", oldIP, pub)
	}
}

func (m *Manager) handleLinkLost(name string, expected Link) {
	m.mu.Lock()
	st := m.states[name]
	if st == nil {
		m.mu.Unlock()
		return
	}
	active := m.active == name
	st.status = StatusFailed
	st.link = Link{}
	st.healthOK = false
	st.publicIP = ""
	st.latencyMS = 0
	st.failureStreak++
	st.lastCheck = time.Now().UTC()
	st.lastError = "PPP interface disappeared; the tunnel is down"
	m.mu.Unlock()
	m.log.Error(name, "PPP interface disappeared; tunnel marked failed")
	_ = m.ops.Cleanup(context.Background(), name)
	if active {
		go m.Failover("active tunnel interface disappeared")
	}
}

func (m *Manager) timerLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case now := <-ticker.C:
			m.mu.Lock()
			due := m.rotationMode == "timer" && !m.nextRotation.IsZero() &&
				!now.Before(m.nextRotation) && !m.timerRunning
			if due {
				m.timerRunning = true
				m.nextRotation = now.Add(time.Duration(m.rotationInterval) * time.Minute)
			}
			m.mu.Unlock()
			if due {
				go func() {
					m.opMu.Lock()
					err := m.rotateLocked(context.Background(), "timer")
					m.opMu.Unlock()
					if err != nil {
						m.log.Warn("", "timer rotation: %v", err)
					}
					m.mu.Lock()
					if m.rotationMode == "timer" {
						m.nextRotation = time.Now().UTC().Add(time.Duration(m.rotationInterval) * time.Minute)
					}
					m.timerRunning = false
					m.mu.Unlock()
				}()
			}
		}
	}
}

// SetRotation changes the automatic rotation mode and interval.
func (m *Manager) SetRotation(mode string, intervalMinutes int) error {
	if mode != "manual" && mode != "timer" && mode != "failover" {
		return errors.New("rotation mode must be manual, timer, or failover")
	}
	if intervalMinutes < m.cfg.Rotation.MinIntervalMinutes || intervalMinutes > m.cfg.Rotation.MaxIntervalMinutes {
		return fmt.Errorf("interval must be between %d and %d minutes", m.cfg.Rotation.MinIntervalMinutes, m.cfg.Rotation.MaxIntervalMinutes)
	}
	m.mu.Lock()
	m.rotationMode = mode
	m.rotationInterval = intervalMinutes
	if mode == "timer" {
		m.nextRotation = time.Now().UTC().Add(time.Duration(intervalMinutes) * time.Minute)
	} else {
		m.nextRotation = time.Time{}
	}
	m.mu.Unlock()
	m.persist(settingRotationMode, mode)
	m.persist(settingRotationInterval, strconv.Itoa(intervalMinutes))
	m.log.Info("", "rotation mode set to %s (interval %d minutes)", mode, intervalMinutes)
	return nil
}

func (m *Manager) StopRotation() error {
	m.mu.RLock()
	interval := m.rotationInterval
	m.mu.RUnlock()
	return m.SetRotation("manual", interval)
}

func (m *Manager) persist(key, value string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.store.SetSetting(ctx, key, value); err != nil {
		m.log.Error("", "could not persist setting %s: %v", key, err)
	}
}

func (m *Manager) restoreLoop() {
	defer m.wg.Done()
	m.mu.RLock()
	last := m.lastActiveWanted
	m.mu.RUnlock()
	if last != "" {
		if t, ok := m.tunnelConfig(last); !ok || !t.Enabled {
			m.log.Warn(last, "last active tunnel is missing or disabled; it will not be restored")
			last = ""
		}
	}
	enabled := []string{}
	for _, name := range m.order {
		if t, ok := m.tunnelConfig(name); ok && t.Enabled {
			enabled = append(enabled, name)
		}
	}
	// Bring the last active tunnel up first so restoration is fast.
	ordered := append([]string{}, enabled...)
	if last != "" {
		ordered = append([]string{last}, ordered...)
		seen := map[string]bool{}
		uniq := ordered[:0]
		for _, n := range ordered {
			if !seen[n] {
				seen[n] = true
				uniq = append(uniq, n)
			}
		}
		ordered = uniq
	}
	for _, name := range ordered {
		select {
		case <-m.ctx.Done():
			return
		default:
		}
		ctx, cancel := context.WithTimeout(m.ctx, 90*time.Second)
		if err := m.Connect(ctx, name); err != nil {
			m.log.Warn(name, "automatic connect failed: %v", err)
		}
		cancel()
	}
	if last == "" {
		return
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	select {
	case <-m.ctx.Done():
		return
	default:
	}
	ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
	defer cancel()
	from, oldIP, newIP, err := m.tryActivateLocked(ctx, last, false)
	if err != nil {
		m.recordRotation(ctx, from, last, "restore", oldIP, "", false, "restore failed: "+m.safeErr(err))
		m.log.Warn(last, "last active tunnel could not be restored: %s", m.safeErr(err))
		m.mu.RLock()
		mode := m.rotationMode
		m.mu.RUnlock()
		if mode == "failover" {
			m.mu.Lock()
			if st := m.states[last]; st != nil && st.status == StatusConnected && m.active == last {
				st.healthOK = false
			}
			if m.active == "" {
				// No active route yet; failover can choose any healthy tunnel.
				m.active = last
			}
			m.mu.Unlock()
			m.Failover("restore of last active tunnel failed")
		}
		return
	}
	m.recordRotation(ctx, from, last, "restore", oldIP, newIP, true, "restored last active tunnel after service start")
	m.log.Info(last, "last active tunnel restored, public IP %s", newIP)
}

// Shutdown stops background work, restores the original uplink, and brings
// tunnels down. The last active name stays persisted for the next boot.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}

	m.opMu.Lock()
	defer m.opMu.Unlock()
	_ = m.ops.RestoreOriginal(ctx)
	for _, name := range m.order {
		m.mu.RLock()
		st := m.states[name]
		var t config.Tunnel
		var connected bool
		if st != nil {
			t = st.cfg
			connected = st.status == StatusConnected || st.status == StatusFailed || st.status == StatusConnecting
		}
		m.mu.RUnlock()
		if connected {
			_ = m.ops.Disconnect(ctx, t)
			_ = m.ops.Cleanup(ctx, name)
		}
	}
	return m.ops.Close(ctx)
}

// TunnelNames returns configured names in order.
func (m *Manager) TunnelNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.order...)
}

// Tunnel returns the configured (secret-bearing refs only) tunnel.
func (m *Manager) Tunnel(name string) (config.Tunnel, bool) { return m.tunnelConfig(name) }

// Healthy reports whether a tunnel is currently a rotation candidate.
func (m *Manager) Healthy(name string) bool {
	now := time.Now().UTC()
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := m.states[name]
	return st != nil && st.healthOK && st.status == StatusConnected &&
		(st.cooldownUntil.IsZero() || !st.cooldownUntil.After(now))
}

// HasPSK reports whether the tunnel's IPsec reference resolves to a stored
// credential. The value itself is never returned.
func (m *Manager) HasPSK(t config.Tunnel) bool {
	return t.IPSecSecretRef != "" && m.secrets.Has(t.IPSecSecretRef)
}
