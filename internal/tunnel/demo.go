package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"tunneld/internal/config"
)

// DemoOps is an explicit, isolated simulation used for UI development and
// rotation-flow testing. It never runs system commands or changes routes.
type DemoOps struct {
	mu       sync.Mutex
	order    []string
	tunnels  map[string]config.Tunnel
	links    map[string]Link
	current  string
	previous Route
}

func NewDemoOps() *DemoOps {
	return &DemoOps{
		tunnels:  map[string]config.Tunnel{},
		links:    map[string]Link{},
		previous: Route{Gateway: "198.51.100.1", Dev: "eth0"},
	}
}

func (d *DemoOps) Init(ctx context.Context, tunnels []config.Tunnel) error {
	return d.Reload(ctx, tunnels)
}

func (d *DemoOps) Reload(ctx context.Context, tunnels []config.Tunnel) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tunnels = map[string]config.Tunnel{}
	d.order = nil
	for _, t := range tunnels {
		d.tunnels[t.Name] = t
		d.order = append(d.order, t.Name)
	}
	return nil
}

func (d *DemoOps) index(name string) int {
	for i, n := range d.order {
		if n == name {
			return i
		}
	}
	return 0
}

func (d *DemoOps) publicIP(name string) string {
	return fmt.Sprintf("203.0.113.%d", 10+d.index(name))
}

func (d *DemoOps) Connect(ctx context.Context, t config.Tunnel) (Link, error) {
	select {
	case <-time.After(350 * time.Millisecond):
	case <-ctx.Done():
		return Link{}, ctx.Err()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	link := Link{
		Iface:   fmt.Sprintf("demo%d", d.index(t.Name)),
		LocalIP: fmt.Sprintf("10.64.0.%d", 2+d.index(t.Name)),
		PeerIP:  fmt.Sprintf("10.64.0.%d", 1+d.index(t.Name)),
		Since:   time.Now().UTC(),
	}
	d.links[t.Name] = link
	return link, nil
}

func (d *DemoOps) Disconnect(ctx context.Context, t config.Tunnel) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.links, t.Name)
	if d.current == t.Name {
		d.current = ""
	}
	return nil
}

func (d *DemoOps) Link(ctx context.Context, name string) (Link, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.links[name]
	return l, ok
}

func (d *DemoOps) Health(ctx context.Context, t config.Tunnel, l Link, timeout time.Duration) (string, time.Duration, error) {
	select {
	case <-time.After(20 * time.Millisecond):
	case <-ctx.Done():
		return "", 0, ctx.Err()
	}
	return d.publicIP(t.Name), time.Duration(11+d.index(t.Name)*3) * time.Millisecond, nil
}

func (d *DemoOps) Activate(ctx context.Context, t config.Tunnel, l Link) (Route, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.links[t.Name]; !ok {
		return Route{}, errors.New("demo tunnel is not connected")
	}
	prev := d.previous
	if d.current != "" {
		prev = Route{Gateway: d.publicIP(d.current), Dev: fmt.Sprintf("demo%d", d.index(d.current))}
	}
	d.current = t.Name
	return prev, nil
}

func (d *DemoOps) VerifyDefault(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.current == "" {
		return "198.51.100.10", nil
	}
	return d.publicIP(d.current), nil
}

func (d *DemoOps) Restore(ctx context.Context, r Route) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current = ""
	return nil
}

func (d *DemoOps) RestoreOriginal(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current = ""
	return nil
}

func (d *DemoOps) Cleanup(ctx context.Context, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.links, name)
	return nil
}

func (d *DemoOps) DefaultRoute(ctx context.Context) (Route, error) {
	return Route{Gateway: "198.51.100.1", Dev: "eth0"}, nil
}

func (d *DemoOps) Close(ctx context.Context) error { return nil }
