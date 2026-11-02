package tunnel

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tunneld/internal/config"
	"tunneld/internal/logx"
	"tunneld/internal/store"
)

// fakeOps is a deterministic in-memory system boundary for manager behavior.
type fakeOps struct {
	mu sync.Mutex

	links      map[string]Link
	ips        map[string]string
	healthErr  map[string]error
	connectErr map[string]error
	active     string
	route      Route
	restores   int
	mismatch   string
}

func newFakeOps(ips map[string]string) *fakeOps {
	return &fakeOps{
		links:      map[string]Link{},
		ips:        ips,
		healthErr:  map[string]error{},
		connectErr: map[string]error{},
		route:      Route{Gateway: "192.0.2.1", Dev: "eth0"},
	}
}

func (f *fakeOps) Init(ctx context.Context, tunnels []config.Tunnel) error { return nil }
func (f *fakeOps) Reload(ctx context.Context, tunnels []config.Tunnel) error { return nil }

func (f *fakeOps) Connect(ctx context.Context, t config.Tunnel) (Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.connectErr[t.Name]; err != nil {
		return Link{}, err
	}
	link := Link{
		Iface:   "ppp-" + t.Name,
		LocalIP: "10.0.0.2",
		PeerIP:  "10.0.0.1",
		Since:   time.Now().UTC(),
	}
	f.links[t.Name] = link
	return link, nil
}

func (f *fakeOps) Disconnect(ctx context.Context, t config.Tunnel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.links, t.Name)
	if f.active == t.Name {
		f.active = ""
	}
	return nil
}

func (f *fakeOps) Link(ctx context.Context, name string) (Link, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[name]
	return l, ok
}

func (f *fakeOps) Health(ctx context.Context, t config.Tunnel, l Link, timeout time.Duration) (string, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.healthErr[t.Name]; err != nil {
		return "", 0, err
	}
	ip, ok := f.ips[t.Name]
	if !ok {
		return "", 0, errors.New("no fake public IP")
	}
	return ip, 4 * time.Millisecond, nil
}

func (f *fakeOps) Activate(ctx context.Context, t config.Tunnel, l Link) (Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev := f.route
	f.active = t.Name
	f.route = Route{Gateway: f.ips[t.Name], Dev: l.Iface}
	return prev, nil
}

func (f *fakeOps) VerifyDefault(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active == "" {
		return "192.0.2.10", nil
	}
	if f.active == f.mismatch {
		return "192.0.2.99", nil
	}
	return f.ips[f.active], nil
}

func (f *fakeOps) Restore(ctx context.Context, r Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restores++
	f.active = ""
	f.route = r
	return nil
}

func (f *fakeOps) RestoreOriginal(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = ""
	f.route = Route{Gateway: "192.0.2.1", Dev: "eth0"}
	return nil
}

func (f *fakeOps) Cleanup(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.links, name)
	return nil
}

func (f *fakeOps) DefaultRoute(ctx context.Context) (Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.route, nil
}

func (f *fakeOps) Close(ctx context.Context) error { return nil }

func testManager(t *testing.T, names ...string) (*Manager, *fakeOps, *store.Store, []config.Tunnel) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Demo = false
	cfg.Database = filepath.Join(dir, "tunneld.db")
	cfg.TunnelsFile = filepath.Join(dir, "tunnels.yaml")
	cfg.SecretsFile = filepath.Join(dir, "secrets.yaml")
	cfg.StateDir = filepath.Join(dir, "run")
	cfg.SwanctlDir = filepath.Join(dir, "swanctl")
	cfg.IPUpDir = filepath.Join(dir, "ip-up.d")
	cfg.IPDownDir = filepath.Join(dir, "ip-down.d")
	cfg.Admin.PasswordHash = "$2a$12$012345678901234567890u0123456789012345678901234567890123"
	cfg.Health.IntervalSeconds = 1
	cfg.Health.TimeoutSeconds = 2
	cfg.Health.FailThreshold = 2
	cfg.Health.CooldownSeconds = 10
	cfg.Rotation.MinHealthy = 2
	cfg.Rotation.VerifyTimeoutSeconds = 5
	cfg.TrustProxy = false

	ips := map[string]string{}
	var tunnels []config.Tunnel
	for i, name := range names {
		ips[name] = fmt.Sprintf("203.0.113.%d", i+10)
		tunnels = append(tunnels, config.Tunnel{
			Name:        name,
			Method:      config.MethodL2TP,
			Server:      fmt.Sprintf("vpn%d.example.net", i+1),
			Username:    "tester",
			PasswordRef: name + "-password",
			Enabled:     true,
			MTU:         1400,
			MRU:         1400,
		})
	}

	st, err := store.Open(cfg.Database)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	secrets, _, err := config.LoadSecrets(cfg.SecretsFile)
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	changes := map[string]*string{}
	for i, name := range names {
		value := fmt.Sprintf("secret-%d", i)
		changes[name+"-password"] = &value
	}
	if err := secrets.SetMany(changes); err != nil {
		t.Fatalf("write secrets: %v", err)
	}
	logger := logx.New(st, secrets, "error")
	ops := newFakeOps(ips)
	m := NewWithOps(&cfg, tunnels, st, secrets, logger, "test", ops)
	return m, ops, st, tunnels
}

func connectAll(t *testing.T, m *Manager, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := m.Connect(context.Background(), name); err != nil {
			t.Fatalf("connect %s: %v", name, err)
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func TestManualRotationSwitchesAndVerifies(t *testing.T) {
	m, ops, st, _ := testManager(t, "alpha", "beta", "gamma")
	defer m.Shutdown(context.Background())
	connectAll(t, m, "alpha", "beta", "gamma")
	if err := m.SetActive(context.Background(), "alpha"); err != nil {
		t.Fatalf("set active: %v", err)
	}

	if err := m.RotateNow(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	snap := m.Snapshot()
	if snap.Active != "beta" {
		t.Fatalf("active = %q, want beta", snap.Active)
	}
	if snap.PublicIP != ops.ips["beta"] {
		t.Fatalf("public IP = %q, want %q", snap.PublicIP, ops.ips["beta"])
	}
	if snap.PreviousPublicIP != ops.ips["alpha"] {
		t.Fatalf("previous IP = %q, want %q", snap.PreviousPublicIP, ops.ips["alpha"])
	}
	if snap.Counts.Healthy != 3 || snap.Counts.Standby != 2 {
		t.Fatalf("unexpected counts: %+v", snap.Counts)
	}

	history, err := st.ListRotations(context.Background(), 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) == 0 || !history[0].Success || history[0].Reason != "manual" {
		t.Fatalf("unexpected history: %+v", history)
	}
}

func TestRotationSkipsWithOnlyOneHealthyTunnel(t *testing.T) {
	m, _, st, _ := testManager(t, "alpha", "beta", "gamma")
	defer m.Shutdown(context.Background())
	connectAll(t, m, "alpha", "beta", "gamma")
	if err := m.SetActive(context.Background(), "alpha"); err != nil {
		t.Fatalf("set active: %v", err)
	}

	m.mu.Lock()
	m.states["beta"].healthOK = false
	m.states["gamma"].healthOK = false
	m.mu.Unlock()

	err := m.RotateNow(context.Background())
	if err == nil || !strings.Contains(err.Error(), "only 1 healthy tunnel") {
		t.Fatalf("rotate error = %v, want single-healthy skip", err)
	}
	if m.Snapshot().Active != "alpha" {
		t.Fatalf("active route changed despite skip")
	}
	history, _ := st.ListRotations(context.Background(), 10)
	if len(history) == 0 || history[0].Success {
		t.Fatalf("expected a failed rotation record, got %+v", history)
	}
}

func TestRotationRollsBackOnMismatchedDefaultRoute(t *testing.T) {
	m, ops, st, _ := testManager(t, "alpha", "beta")
	defer m.Shutdown(context.Background())
	connectAll(t, m, "alpha", "beta")
	if err := m.SetActive(context.Background(), "alpha"); err != nil {
		t.Fatalf("set active: %v", err)
	}
	ops.mu.Lock()
	ops.mismatch = "beta"
	ops.mu.Unlock()

	err := m.RotateNow(context.Background())
	if err == nil || !strings.Contains(err.Error(), "default route exits with") {
		t.Fatalf("rotate error = %v, want route mismatch", err)
	}
	snap := m.Snapshot()
	if snap.Active != "alpha" || snap.PublicIP != ops.ips["alpha"] {
		t.Fatalf("rollback failed: active=%q ip=%q", snap.Active, snap.PublicIP)
	}
	ops.mu.Lock()
	restores := ops.restores
	ops.mu.Unlock()
	if restores == 0 {
		t.Fatal("previous route was not restored")
	}
	history, _ := st.ListRotations(context.Background(), 10)
	if len(history) == 0 || history[0].Success {
		t.Fatalf("expected failed history entry, got %+v", history)
	}
}

func TestFailoverSwitchesToHealthyStandby(t *testing.T) {
	m, _, st, _ := testManager(t, "alpha", "beta")
	defer m.Shutdown(context.Background())
	connectAll(t, m, "alpha", "beta")
	if err := m.SetActive(context.Background(), "alpha"); err != nil {
		t.Fatalf("set active: %v", err)
	}
	m.mu.Lock()
	m.states["alpha"].healthOK = false
	m.mu.Unlock()

	m.Failover("test failure")
	if m.Snapshot().Active != "beta" {
		t.Fatalf("failover did not switch: active=%q", m.Snapshot().Active)
	}
	history, _ := st.ListRotations(context.Background(), 10)
	if len(history) == 0 || !history[0].Success || history[0].Reason != "failover" {
		t.Fatalf("unexpected history: %+v", history)
	}
}

func TestTimerRotationRuns(t *testing.T) {
	m, _, st, _ := testManager(t, "alpha", "beta")
	defer m.Shutdown(context.Background())
	connectAll(t, m, "alpha", "beta")
	if err := m.SetActive(context.Background(), "alpha"); err != nil {
		t.Fatalf("set active: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := m.SetRotation("timer", 1); err != nil {
		t.Fatalf("set timer: %v", err)
	}
	m.mu.Lock()
	m.nextRotation = time.Now().Add(-time.Second)
	m.mu.Unlock()

	if !waitFor(t, 4*time.Second, func() bool { return m.Snapshot().Active == "beta" }) {
		t.Fatalf("timer rotation did not run; active=%q", m.Snapshot().Active)
	}
	history, _ := st.ListRotations(context.Background(), 10)
	found := false
	for _, h := range history {
		if h.Success && h.Reason == "timer" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no successful timer rotation in %+v", history)
	}
}

func TestRestoreLastActiveTunnel(t *testing.T) {
	m, _, st, _ := testManager(t, "alpha", "beta")
	defer m.Shutdown(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := st.SetSetting(ctx, settingLastActive, "beta"); err != nil {
		t.Fatalf("persist last active: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !waitFor(t, 4*time.Second, func() bool { return m.Snapshot().Active == "beta" }) {
		t.Fatalf("last active tunnel was not restored; active=%q", m.Snapshot().Active)
	}
	history, _ := st.ListRotations(context.Background(), 10)
	found := false
	for _, h := range history {
		if h.Success && h.Reason == "restore" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no successful restore history in %+v", history)
	}
}
