package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunneld/internal/config"
	"tunneld/internal/logx"
)

type policy struct {
	localIP  string
	table    int
	priority int
}

type LinuxOps struct {
	cfg     *config.Config
	secrets *config.SecretStore
	log     *logx.Logger
	run     Runner

	mu         sync.Mutex
	tunnels    map[string]config.Tunnel
	original   Route
	haveOrigin bool
	policies   map[string]policy
	ppp        map[string]*managedProc
	xl         *managedProc
	xlDirty    bool
	index      map[string]int
}

func NewLinuxOps(cfg *config.Config, secrets *config.SecretStore, logger *logx.Logger) *LinuxOps {
	return &LinuxOps{
		cfg:      cfg,
		secrets:  secrets,
		log:      logger,
		tunnels:  map[string]config.Tunnel{},
		policies: map[string]policy{},
		ppp:      map[string]*managedProc{},
		index:    map[string]int{},
	}
}

func (l *LinuxOps) Init(ctx context.Context, tunnels []config.Tunnel) error {
	if err := l.ensureLayout(); err != nil {
		return err
	}
	var errs []error
	if err := l.installHooks(); err != nil {
		errs = append(errs, err)
	}
	if err := l.writeGeneratedFiles(tunnels); err != nil {
		errs = append(errs, err)
	}
	if err := l.detectOriginal(ctx); err != nil {
		errs = append(errs, err)
	}
	l.mu.Lock()
	l.tunnels = map[string]config.Tunnel{}
	l.index = map[string]int{}
	for i, t := range tunnels {
		l.tunnels[t.Name] = t
		l.index[t.Name] = i
	}
	l.mu.Unlock()
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (l *LinuxOps) Reload(ctx context.Context, tunnels []config.Tunnel) error {
	if err := l.writeGeneratedFiles(tunnels); err != nil {
		return err
	}
	l.mu.Lock()
	l.tunnels = map[string]config.Tunnel{}
	l.index = map[string]int{}
	for i, t := range tunnels {
		l.tunnels[t.Name] = t
		l.index[t.Name] = i
	}
	l2tpEnabled := len(generatedL2TPNames(tunnels)) > 0
	xl := l.xl
	l.mu.Unlock()

	// xl2tpd does not reload [lac] sections. If no L2TP tunnel is currently
	// connected we can restart it immediately; otherwise defer to the next
	// L2TP connect so rotation traffic is not disturbed by an edit.
	connectedL2TP := 0
	for _, t := range tunnels {
		if t.Method != config.MethodL2TP {
			continue
		}
		if _, ok := l.Link(ctx, t.Name); ok {
			connectedL2TP++
		}
	}
	if xl != nil {
		switch {
		case !l2tpEnabled:
			_ = l.stopManaged(xl)
			l.mu.Lock()
			l.xl = nil
			l.xlDirty = false
			l.mu.Unlock()
		case connectedL2TP > 0:
			l.mu.Lock()
			l.xlDirty = true
			l.mu.Unlock()
			l.log.Warn("", "xl2tpd config changed while L2TP tunnels are connected; the daemon will reload on the next L2TP connect")
		default:
			_ = l.stopManaged(xl)
			l.mu.Lock()
			l.xl = nil
			l.mu.Unlock()
			if err := l.startXL2TPD(ctx); err != nil {
				return err
			}
		}
	}

	// Reload strongSwan configuration if the daemon is available. This does
	// not tear down active SAs.
	if _, err := os.Stat(l.cfg.SwanctlDir); err == nil {
		loadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, _, err := l.run.Run(loadCtx, l.cfg.Commands.Swanctl, "--load-all")
		cancel()
		if err != nil {
			l.log.Debug("", "strongSwan config not loaded (daemon may be stopped): %v", err)
		}
	}
	return nil
}

func (l *LinuxOps) detectOriginal(ctx context.Context) error {
	cur, err := l.currentDefault(ctx)
	if err == nil && cur.Dev != "" && !strings.HasPrefix(cur.Dev, "ppp") {
		l.mu.Lock()
		l.original = cur
		l.haveOrigin = true
		l.mu.Unlock()
		_ = config.WriteFileAtomic(l.originalRoutePath(), []byte(cur.Gateway+"\n"+cur.Dev+"\n"), 0o600)
		return nil
	}
	// If the app crashed while a tunnel was active, the saved pre-tunnel route
	// is the only safe way back to the real uplink.
	if b, err := os.ReadFile(l.originalRoutePath()); err == nil {
		parts := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(parts) >= 2 && parts[1] != "" && !strings.HasPrefix(parts[1], "ppp") {
			l.mu.Lock()
			l.original = Route{Gateway: strings.TrimSpace(parts[0]), Dev: strings.TrimSpace(parts[1])}
			l.haveOrigin = true
			l.mu.Unlock()
			return nil
		}
	}
	if l.cfg.Network.UplinkGateway != "" && l.cfg.Network.UplinkInterface != "" {
		l.mu.Lock()
		l.original = Route{Gateway: l.cfg.Network.UplinkGateway, Dev: l.cfg.Network.UplinkInterface}
		l.haveOrigin = true
		l.mu.Unlock()
		return nil
	}
	return fmt.Errorf("cannot determine the original uplink route; set network.uplink_gateway and network.uplink_interface in the config")
}

func (l *LinuxOps) originalRoutePath() string {
	return filepath.Join(l.cfg.StateDir, "original-route")
}

func (l *LinuxOps) originalRoute() (Route, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.original, l.haveOrigin
}

// currentDefault returns the first IPv4 default route.
func (l *LinuxOps) currentDefault(ctx context.Context) (Route, error) {
	out, _, err := l.run.Run(ctx, l.cfg.Commands.IP, "-4", "-j", "route", "show", "default")
	if err != nil {
		return Route{}, err
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
		Metric  int    `json:"metric"`
	}
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		return Route{}, fmt.Errorf("parse default route: %w", err)
	}
	if len(routes) == 0 {
		return Route{}, errors.New("no IPv4 default route is present")
	}
	return Route{Gateway: routes[0].Gateway, Dev: routes[0].Dev}, nil
}

func (l *LinuxOps) DefaultRoute(ctx context.Context) (Route, error) {
	return l.currentDefault(ctx)
}

func (l *LinuxOps) ensureHostRoute(ctx context.Context, server string) (string, error) {
	orig, ok := l.originalRoute()
	if !ok {
		return "", errors.New("original uplink route is unknown")
	}
	if strings.HasPrefix(orig.Dev, "ppp") {
		return "", errors.New("refusing to add a tunnel host route through a PPP device; original uplink detection is wrong")
	}
	ip, err := resolveIPv4(ctx, server)
	if err != nil {
		return "", err
	}
	if l.cfg.Network.HostRoute {
		args := []string{"-4", "route", "replace", ip + "/32"}
		if orig.Gateway != "" {
			args = append(args, "via", orig.Gateway)
		}
		args = append(args, "dev", orig.Dev)
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, _, err := l.run.Run(rctx, l.cfg.Commands.IP, args...)
		cancel()
		if err != nil {
			return "", fmt.Errorf("add host route to tunnel server %s: %w", ip, err)
		}
	}
	return ip, nil
}

func resolveIPv4(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("%s is not an IPv4 address", host)
		}
		return ip.To4().String(), nil
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve %s: no IPv4 address", host)
	}
	return ips[0].String(), nil
}

func (l *LinuxOps) installPolicy(ctx context.Context, name string, link Link) error {
	l.mu.Lock()
	idx, ok := l.index[name]
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("tunnel %s has no configuration index", name)
	}
	table := l.cfg.Network.RouteTableBase + idx
	priority := l.cfg.Network.RulePriorityBase + idx

	// Recreate a clean source policy: everything sourced from this tunnel's
	// local IP uses a dedicated table whose default is the PPP interface.
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, _, _ = l.run.Run(rctx, l.cfg.Commands.IP, "-4", "route", "flush", "table", strconv.Itoa(table))
	if _, _, err := l.run.Run(rctx, l.cfg.Commands.IP, "-4", "route", "replace", "default", "dev", link.Iface, "table", strconv.Itoa(table)); err != nil {
		return fmt.Errorf("add policy route table: %w", err)
	}
	// Remove any previous rule at this priority (local IP may have changed).
	_, _, _ = l.run.Run(rctx, l.cfg.Commands.IP, "-4", "rule", "del", "priority", strconv.Itoa(priority))
	if _, _, err := l.run.Run(rctx, l.cfg.Commands.IP, "-4", "rule", "add", "from", link.LocalIP+"/32",
		"priority", strconv.Itoa(priority), "lookup", strconv.Itoa(table)); err != nil {
		return fmt.Errorf("add policy rule: %w", err)
	}
	l.mu.Lock()
	l.policies[name] = policy{localIP: link.LocalIP, table: table, priority: priority}
	l.mu.Unlock()
	return nil
}

func (l *LinuxOps) cleanupPolicy(ctx context.Context, name string) {
	l.mu.Lock()
	p, ok := l.policies[name]
	delete(l.policies, name)
	l.mu.Unlock()
	if !ok {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, _, _ = l.run.Run(rctx, l.cfg.Commands.IP, "-4", "rule", "del", "priority", strconv.Itoa(p.priority))
	_, _, _ = l.run.Run(rctx, l.cfg.Commands.IP, "-4", "route", "flush", "table", strconv.Itoa(p.table))
}

func (l *LinuxOps) Activate(ctx context.Context, t config.Tunnel, link Link) (Route, error) {
	prev, err := l.currentDefault(ctx)
	if err != nil {
		return prev, err
	}
	if prev.Dev == "" {
		return prev, errors.New("current default route has no device")
	}
	if _, err := l.ensureHostRoute(ctx, t.Server); err != nil {
		return prev, err
	}
	args := []string{"-4", "route", "replace", "default"}
	if link.PeerIP != "" {
		args = append(args, "via", link.PeerIP)
	}
	args = append(args, "dev", link.Iface)
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, _, err := l.run.Run(rctx, l.cfg.Commands.IP, args...); err != nil {
		return prev, fmt.Errorf("set default route via %s: %w", link.Iface, err)
	}
	return prev, nil
}

func (l *LinuxOps) VerifyDefault(ctx context.Context) (string, error) {
	ip, _, err := l.checkPublicIP(ctx, "")
	return ip, err
}

func (l *LinuxOps) Restore(ctx context.Context, r Route) error {
	if r.Dev == "" {
		return errors.New("rollback route has no device")
	}
	args := []string{"-4", "route", "replace", "default"}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	args = append(args, "dev", r.Dev)
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, _, err := l.run.Run(rctx, l.cfg.Commands.IP, args...); err != nil {
		return fmt.Errorf("restore default route via %s: %w", r.Dev, err)
	}
	return nil
}

func (l *LinuxOps) RestoreOriginal(ctx context.Context) error {
	orig, ok := l.originalRoute()
	if !ok {
		return errors.New("original uplink route is unknown")
	}
	return l.Restore(ctx, orig)
}

func (l *LinuxOps) Cleanup(ctx context.Context, name string) error {
	l.cleanupPolicy(ctx, name)
	_ = os.Remove(linkStatePath(l.cfg.StateDir, name))
	return nil
}

func (l *LinuxOps) Link(ctx context.Context, name string) (Link, bool) {
	l.mu.Lock()
	proc := l.ppp[name]
	l.mu.Unlock()
	if proc != nil && proc.exited() {
		return Link{}, false
	}
	link, err := readLinkState(l.cfg.StateDir, name)
	if err != nil {
		return Link{}, false
	}
	if !l.interfaceHasIP(ctx, link.Iface, link.LocalIP) {
		_ = os.Remove(linkStatePath(l.cfg.StateDir, name))
		return Link{}, false
	}
	return link, true
}

func (l *LinuxOps) interfaceHasIP(ctx context.Context, iface, want string) bool {
	if iface == "" || strings.ContainsAny(iface, " \t\r\n/") {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _, err := l.run.Run(rctx, l.cfg.Commands.IP, "-4", "-j", "addr", "show", "dev", iface)
	if err != nil {
		return false
	}
	var addrs []struct {
		IfName   string `json:"ifname"`
		AddrInfo []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(out), &addrs); err != nil {
		return false
	}
	for _, a := range addrs {
		for _, ai := range a.AddrInfo {
			if ai.Family == "inet" && (want == "" || ai.Local == want) {
				return true
			}
		}
	}
	return false
}

func readLinkState(stateDir, name string) (Link, error) {
	b, err := os.ReadFile(linkStatePath(stateDir, name))
	if err != nil {
		return Link{}, err
	}
	parts := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(parts) < 3 {
		return Link{}, errors.New("malformed interface state")
	}
	iface := strings.TrimSpace(parts[0])
	if iface == "" || len(iface) > 15 || strings.ContainsAny(iface, " \t\r\n/") {
		return Link{}, errors.New("invalid interface name in state file")
	}
	local, peer := strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
	if net.ParseIP(local) == nil || net.ParseIP(local).To4() == nil {
		return Link{}, errors.New("invalid local tunnel IP")
	}
	if peer != "" && net.ParseIP(peer) == nil {
		peer = ""
	}
	since := time.Now()
	if len(parts) >= 4 {
		if n, err := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64); err == nil {
			since = time.Unix(n, 0)
		}
	}
	return Link{Iface: iface, LocalIP: local, PeerIP: peer, Since: since}, nil
}

var pingTimeRe = regexp.MustCompile(`time[=<]([0-9.]+)\s*ms`)

func (l *LinuxOps) Health(ctx context.Context, t config.Tunnel, link Link, timeout time.Duration) (string, time.Duration, error) {
	if link.Iface == "" || link.LocalIP == "" {
		return "", 0, errors.New("tunnel has no live PPP interface")
	}
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	pingSecs := int(timeout.Seconds())
	if pingSecs < 1 {
		pingSecs = 1
	}
	out, errOut, pingErr := l.run.Run(pingCtx, l.cfg.Commands.Ping,
		"-n", "-4", "-c", "1", "-W", strconv.Itoa(pingSecs), "-I", link.Iface, "1.1.1.1")
	cancel()
	latency := time.Duration(0)
	if pingErr == nil {
		if m := pingTimeRe.FindStringSubmatch(out); len(m) == 2 {
			if f, err := strconv.ParseFloat(m[1], 64); err == nil {
				latency = time.Duration(f * float64(time.Millisecond))
			}
		}
	} else {
		_ = errOut
		l.log.Debug(t.Name, "ICMP health check failed (continuing to public-IP check): %v", pingErr)
	}

	ip, ipLatency, err := l.checkPublicIP(ctx, link.Iface)
	if err != nil {
		if pingErr != nil {
			return "", 0, fmt.Errorf("ping and public IP check failed: %v; %w", pingErr, err)
		}
		return "", 0, err
	}
	if latency == 0 {
		latency = ipLatency
	}
	return ip, latency, nil
}

func (l *LinuxOps) checkPublicIP(ctx context.Context, iface string) (string, time.Duration, error) {
	timeout := l.cfg.Health.Timeout()
	var lastErr error
	for _, url := range l.cfg.CheckerURLs {
		start := time.Now()
		cctx, cancel := context.WithTimeout(ctx, timeout)
		args := []string{"-4", "-fsS", "--max-time", strconv.Itoa(int(timeout.Seconds())), "--connect-timeout", "4"}
		if iface != "" {
			args = append(args, "--interface", iface)
		}
		args = append(args, url)
		out, _, err := l.run.Run(cctx, l.cfg.Commands.Curl, args...)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		body := strings.TrimSpace(out)
		if len(body) > 64 {
			body = body[:64]
		}
		ip := net.ParseIP(body)
		if ip == nil || ip.To4() == nil {
			lastErr = fmt.Errorf("checker %s returned an invalid IPv4 address", url)
			continue
		}
		return ip.To4().String(), time.Since(start), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no public IP checker is configured")
	}
	target := "through the tunnel"
	if iface == "" {
		target = "through the default route"
	}
	return "", 0, fmt.Errorf("public IP check %s failed: %w", target, lastErr)
}

func (l *LinuxOps) Close(ctx context.Context) error {
	l.mu.Lock()
	procs := make([]*managedProc, 0, len(l.ppp)+1)
	for _, p := range l.ppp {
		procs = append(procs, p)
	}
	if l.xl != nil {
		procs = append(procs, l.xl)
	}
	l.ppp = map[string]*managedProc{}
	l.xl = nil
	l.mu.Unlock()
	for _, p := range procs {
		_ = l.stopManaged(p)
	}
	return nil
}

func (l *LinuxOps) installHooks() error {
	stateDir := l.cfg.StateDir
	up := fmt.Sprintf(`#!/bin/sh
# Generated by tunneld. Records the live PPP interface for a tunnel name.
name="$6"
[ -n "$name" ] || exit 0
case "$name" in *[!A-Za-z0-9_-]*) exit 0 ;; esac
dir=%s
mkdir -p "$dir" 2>/dev/null || exit 0
umask 077
tmp="$dir/.$name.$$"
printf '%%s\n%%s\n%%s\n%%s\n' "$1" "$4" "$5" "$(date +%%s)" > "$tmp" || exit 0
mv "$tmp" "$dir/$name" 2>/dev/null || rm -f "$tmp"
`, shellQuote(filepath.Join(stateDir, "ifaces")))
	down := fmt.Sprintf(`#!/bin/sh
# Generated by tunneld. Removes a tunnel's interface state after PPP goes down.
name="$6"
[ -n "$name" ] || exit 0
case "$name" in *[!A-Za-z0-9_-]*) exit 0 ;; esac
dir=%s
file="$dir/$name"
[ -f "$file" ] || exit 0
iface=$(sed -n '1p' "$file" 2>/dev/null)
[ "$iface" = "$1" ] && rm -f "$file"
exit 0
`, shellQuote(filepath.Join(stateDir, "ifaces")))
	for _, item := range []struct {
		path    string
		content string
	}{
		{filepath.Join(l.cfg.IPUpDir, "tunneld"), up},
		{filepath.Join(l.cfg.IPDownDir, "tunneld"), down},
	} {
		if err := os.MkdirAll(filepath.Dir(item.path), 0o755); err != nil {
			return fmt.Errorf("create PPP hook directory: %w", err)
		}
		if err := config.WriteFileAtomic(item.path, []byte(item.content), 0o755); err != nil {
			return fmt.Errorf("install PPP hook %s: %w", item.path, err)
		}
	}
	return nil
}
