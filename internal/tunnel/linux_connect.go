package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tunneld/internal/config"
)

type managedProc struct {
	label  string
	tunnel string
	name   string
	cmd    *exec.Cmd
	done   chan struct{}

	mu      sync.Mutex
	waitErr error
	ended   bool
	lines   []string
}

func (l *LinuxOps) startManaged(name, label, tunnel string, args ...string) (*managedProc, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", shortName(name), err)
	}
	p := &managedProc{
		label:  label,
		tunnel: tunnel,
		name:   shortName(name),
		cmd:    cmd,
		done:   make(chan struct{}),
	}
	go p.scan(stderr, l)
	go p.scan(stdout, l)
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.waitErr = err
		p.ended = true
		p.mu.Unlock()
		close(p.done)
	}()
	l.log.Info(tunnel, "%s started (pid %d)", p.name, cmd.Process.Pid)
	return p, nil
}

func (p *managedProc) scan(r interface{ Read([]byte) (int, error) }, l *LinuxOps) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		p.mu.Lock()
		p.lines = append(p.lines, line)
		if len(p.lines) > 30 {
			p.lines = p.lines[len(p.lines)-30:]
		}
		p.mu.Unlock()
		l.log.Info(p.tunnel, "%s: %s", p.name, line)
	}
}

func (p *managedProc) isExited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ended
}

func (p *managedProc) exited() bool { return p.isExited() }

func (p *managedProc) lastLines(n int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lines) == 0 {
		return ""
	}
	start := len(p.lines) - n
	if start < 0 {
		start = 0
	}
	return strings.Join(p.lines[start:], " | ")
}

func (p *managedProc) lastErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.waitErr != nil {
		return p.waitErr
	}
	if p.ended {
		return errors.New("process exited")
	}
	return nil
}

func (l *LinuxOps) stopManaged(p *managedProc) error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	if p.isExited() {
		return nil
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
		return nil
	case <-time.After(8 * time.Second):
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-p.done:
		return nil
	case <-time.After(3 * time.Second):
		return fmt.Errorf("process %s (pid %d) did not stop", p.name, p.cmd.Process.Pid)
	}
}

func (l *LinuxOps) startXL2TPD(ctx context.Context) error {
	l.mu.Lock()
	if l.xl != nil && !l.xl.isExited() {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()

	if _, err := os.Stat(xl2tpdConfigPath(l.cfg.StateDir)); err != nil {
		return fmt.Errorf("xl2tpd config is missing: %w", err)
	}
	_ = os.Remove(xl2tpdControlPath(l.cfg.StateDir))
	p, err := l.startManaged(l.cfg.Commands.Xl2tpd, "xl2tpd", "",
		"-D", "-c", xl2tpdConfigPath(l.cfg.StateDir),
		"-p", xl2tpdPIDPath(l.cfg.StateDir),
		"-C", xl2tpdControlPath(l.cfg.StateDir))
	if err != nil {
		return fmt.Errorf("start xl2tpd: %w", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if p.isExited() {
			return fmt.Errorf("xl2tpd exited during startup: %s", p.lastLines(6))
		}
		if info, err := os.Stat(xl2tpdControlPath(l.cfg.StateDir)); err == nil && info.Mode()&os.ModeNamedPipe != 0 {
			l.mu.Lock()
			l.xl = p
			l.xlDirty = false
			l.mu.Unlock()
			return nil
		}
		select {
		case <-ctx.Done():
			_ = l.stopManaged(p)
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	_ = l.stopManaged(p)
	return fmt.Errorf("xl2tpd control socket did not appear: %s", p.lastLines(6))
}

func (l *LinuxOps) stopXL2TPD() {
	l.mu.Lock()
	p := l.xl
	l.xl = nil
	l.mu.Unlock()
	if p != nil {
		_ = l.stopManaged(p)
	}
	_ = os.Remove(xl2tpdControlPath(l.cfg.StateDir))
	_ = os.Remove(xl2tpdPIDPath(l.cfg.StateDir))
}

func (l *LinuxOps) sendControl(command string) error {
	path := xl2tpdControlPath(l.cfg.StateDir)
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("xl2tpd control file: %w", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("xl2tpd control path is not a FIFO")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open xl2tpd control file: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(command + "\n")
	return err
}

func (l *LinuxOps) Connect(ctx context.Context, t config.Tunnel) (Link, error) {
	if t.Server == "" {
		return Link{}, errors.New("tunnel server is empty")
	}
	if _, err := l.ensureHostRoute(ctx, t.Server); err != nil {
		return Link{}, err
	}
	switch t.Method {
	case config.MethodL2TP:
		return l.connectL2TP(ctx, t)
	case config.MethodSSTP, config.MethodPPTP:
		return l.connectPPP(ctx, t)
	default:
		return Link{}, fmt.Errorf("unsupported method %q", t.Method)
	}
}

func (l *LinuxOps) connectL2TP(ctx context.Context, t config.Tunnel) (Link, error) {
	l.mu.Lock()
	dirty := l.xlDirty
	l.mu.Unlock()
	if dirty {
		l.log.Warn(t.Name, "restarting xl2tpd to apply configuration changes")
		l.stopXL2TPD()
	}
	if t.UseIPSec {
		if err := l.setupIPsec(ctx, t); err != nil {
			return Link{}, err
		}
	}
	if err := l.startXL2TPD(ctx); err != nil {
		if t.UseIPSec {
			l.teardownIPsec(ctx, t)
		}
		return Link{}, err
	}
	if err := l.sendControl("c " + t.Name); err != nil {
		if t.UseIPSec {
			l.teardownIPsec(ctx, t)
		}
		return Link{}, fmt.Errorf("ask xl2tpd to connect %s: %w", t.Name, err)
	}
	l.mu.Lock()
	xl := l.xl
	l.mu.Unlock()
	link, err := l.waitLink(ctx, t.Name, xl, 75*time.Second)
	if err != nil {
		_ = l.sendControl("d " + t.Name)
		if t.UseIPSec {
			l.teardownIPsec(ctx, t)
		}
		_ = l.cleanupStalePPP(t.Name)
		return Link{}, fmt.Errorf("L2TP connect failed: %w", err)
	}
	if err := l.installPolicy(ctx, t.Name, link); err != nil {
		_ = l.sendControl("d " + t.Name)
		if t.UseIPSec {
			l.teardownIPsec(ctx, t)
		}
		return Link{}, err
	}
	return link, nil
}

func (l *LinuxOps) setupIPsec(ctx context.Context, t config.Tunnel) error {
	path := swanctlPath(l.cfg.SwanctlDir, t.Name)
	if _, err := os.Stat(path); err != nil {
		content, gerr := generateSwanctl(l.cfg, l.secrets, t)
		if gerr != nil {
			return gerr
		}
		if werr := config.WriteFileAtomic(path, []byte(content), 0o600); werr != nil {
			return fmt.Errorf("write IPsec config: %w", werr)
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	_, _, err := l.run.Run(rctx, l.cfg.Commands.Swanctl, "--load-all")
	cancel()
	if err != nil {
		return fmt.Errorf("strongSwan is not available or rejected the configuration: %w", err)
	}
	name := "tunneld-" + t.Name
	rctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	_, _, err = l.run.Run(rctx, l.cfg.Commands.Swanctl, "--initiate", "--child", name)
	cancel()
	if err != nil {
		return fmt.Errorf("initiate IPsec for %s: %w", t.Name, err)
	}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		lctx, lcancel := context.WithTimeout(ctx, 8*time.Second)
		out, _, lerr := l.run.Run(lctx, l.cfg.Commands.Swanctl, "--list-sas")
		lcancel()
		if lerr == nil && strings.Contains(out, name) && strings.Contains(out, "ESTABLISHED") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("IPsec SA for %s did not become ESTABLISHED", t.Name)
}

func (l *LinuxOps) teardownIPsec(ctx context.Context, t config.Tunnel) {
	name := "tunneld-" + t.Name
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, _, err := l.run.Run(rctx, l.cfg.Commands.Swanctl, "--terminate", "--ike", name); err != nil {
		_, _, _ = l.run.Run(rctx, l.cfg.Commands.Swanctl, "--terminate", "--child", name)
	}
}

func (l *LinuxOps) connectPPP(ctx context.Context, t config.Tunnel) (Link, error) {
	opts := pppOptionsPath(l.cfg.StateDir, t.Name)
	if _, err := os.Stat(opts); err != nil {
		content, gerr := generatePPP(l.cfg, l.secrets, t)
		if gerr != nil {
			return Link{}, gerr
		}
		if werr := config.WriteFileAtomic(opts, []byte(content), 0o600); werr != nil {
			return Link{}, fmt.Errorf("write PPP options: %w", werr)
		}
	}
	p, err := l.startManaged(l.cfg.Commands.Pppd, "pppd", t.Name, "nodetach", "file", opts)
	if err != nil {
		return Link{}, fmt.Errorf("%s connect failed: %w", t.Method, err)
	}
	l.mu.Lock()
	l.ppp[t.Name] = p
	l.mu.Unlock()
	link, err := l.waitLink(ctx, t.Name, p, 75*time.Second)
	if err != nil {
		_ = l.stopManaged(p)
		l.mu.Lock()
		delete(l.ppp, t.Name)
		l.mu.Unlock()
		return Link{}, fmt.Errorf("%s connect failed: %w", t.Method, err)
	}
	if err := l.installPolicy(ctx, t.Name, link); err != nil {
		_ = l.stopManaged(p)
		l.mu.Lock()
		delete(l.ppp, t.Name)
		l.mu.Unlock()
		return Link{}, err
	}
	return link, nil
}

func (l *LinuxOps) waitLink(ctx context.Context, name string, proc *managedProc, timeout time.Duration) (Link, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if proc != nil && proc.isExited() {
			msg := proc.lastLines(8)
			if msg == "" {
				msg = "process exited without output"
			}
			return Link{}, fmt.Errorf("PPP process exited before the interface came up: %s", msg)
		}
		if link, ok := l.Link(ctx, name); ok {
			return link, nil
		}
		select {
		case <-ctx.Done():
			return Link{}, ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
	}
	if proc != nil {
		if msg := proc.lastLines(8); msg != "" {
			return Link{}, fmt.Errorf("timed out waiting for %s to come up: %s", name, msg)
		}
	}
	return Link{}, fmt.Errorf("timed out waiting for %s to come up", name)
}

func (l *LinuxOps) Disconnect(ctx context.Context, t config.Tunnel) error {
	switch t.Method {
	case config.MethodL2TP:
		var err error
		if l.xlAlive() {
			err = l.sendControl("d " + t.Name)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := l.Link(ctx, t.Name); !ok {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
		}
		if _, still := l.Link(ctx, t.Name); still {
			_ = l.cleanupStalePPP(t.Name)
			time.Sleep(500 * time.Millisecond)
			if _, again := l.Link(ctx, t.Name); again {
				if err != nil {
					return fmt.Errorf("disconnect %s: %w", t.Name, err)
				}
				return fmt.Errorf("disconnect %s: PPP interface is still present", t.Name)
			}
		}
		if t.UseIPSec {
			l.teardownIPsec(ctx, t)
		}
		l.cleanupPolicy(ctx, t.Name)
		_ = os.Remove(linkStatePath(l.cfg.StateDir, t.Name))
		return nil
	case config.MethodSSTP, config.MethodPPTP:
		l.mu.Lock()
		p := l.ppp[t.Name]
		delete(l.ppp, t.Name)
		l.mu.Unlock()
		if p != nil {
			if err := l.stopManaged(p); err != nil {
				return err
			}
		}
		l.cleanupPolicy(ctx, t.Name)
		_ = os.Remove(linkStatePath(l.cfg.StateDir, t.Name))
		return nil
	default:
		return fmt.Errorf("unsupported method %q", t.Method)
	}
}

func (l *LinuxOps) xlAlive() bool {
	l.mu.Lock()
	p := l.xl
	l.mu.Unlock()
	return p != nil && !p.isExited()
}

// cleanupStalePPP kills only pppd processes whose ipparam exactly matches the
// tunnel name. It never matches by interface number or broad process pattern.
func (l *LinuxOps) cleanupStalePPP(name string) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(b), "\x00")
		if !strings.Contains(filepath.Base(args[0]), "pppd") {
			continue
		}
		match := false
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "ipparam" && args[i+1] == name {
				match = true
				break
			}
		}
		if !match {
			want := pppOptionsPath(l.cfg.StateDir, name)
			for _, a := range args {
				if a == want || strings.HasSuffix(a, "/"+name+".options") {
					match = true
					break
				}
			}
		}
		if match {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	return nil
}
