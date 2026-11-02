package tunnel

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"tunneld/internal/config"
)

// AddTunnel validates, stores credentials, writes tunnels.yaml, and generates
// the method-specific system configuration. password is required.
func (m *Manager) AddTunnel(ctx context.Context, t config.Tunnel, password, psk *string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	config.NormalizeTunnel(&t)
	if t.PasswordRef == "" {
		t.PasswordRef = t.Name + "-password"
	}
	if t.Method == config.MethodL2TP && t.UseIPSec && t.IPSecSecretRef == "" {
		t.IPSecSecretRef = t.Name + "-psk"
	}
	if password == nil || strings.TrimSpace(*password) == "" {
		return errors.New("a password is required when adding a tunnel")
	}
	if t.Method == config.MethodL2TP && t.UseIPSec {
		if psk == nil || strings.TrimSpace(*psk) == "" {
			return errors.New("an IPsec pre-shared key is required when use_ipsec is true")
		}
	}

	m.mu.RLock()
	tunnels := m.configListLocked()
	m.mu.RUnlock()
	if _, exists := m.tunnelConfig(t.Name); exists {
		return fmt.Errorf("tunnel %q already exists", t.Name)
	}
	tunnels = append(tunnels, t)
	if err := config.ValidateTunnels(tunnels); err != nil {
		return err
	}

	changes := map[string]*string{t.PasswordRef: password}
	if t.IPSecSecretRef != "" && psk != nil {
		changes[t.IPSecSecretRef] = psk
	}
	if err := m.secrets.SetMany(changes); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	if err := config.SaveTunnels(m.cfg.TunnelsFile, tunnels); err != nil {
		return fmt.Errorf("save tunnels: %w", err)
	}

	m.mu.Lock()
	m.addStateLocked(t)
	m.mu.Unlock()
	m.log.Info(t.Name, "tunnel added (%s to %s)", t.Method, t.Server)
	return m.reloadLocked(ctx, tunnels)
}

// UpdateTunnel updates an existing tunnel. The name is immutable. A nil or
// empty password/psk means "keep the existing secret".
func (m *Manager) UpdateTunnel(ctx context.Context, name string, t config.Tunnel, password, psk *string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	old, ok := m.tunnelConfig(name)
	if !ok {
		return fmt.Errorf("tunnel %q is not configured", name)
	}
	if t.Name != name {
		return errors.New("tunnel name cannot be changed; delete and recreate the tunnel instead")
	}
	config.NormalizeTunnel(&t)
	if t.PasswordRef == "" {
		t.PasswordRef = old.PasswordRef
	}
	if t.Method == config.MethodL2TP && t.UseIPSec && t.IPSecSecretRef == "" {
		t.IPSecSecretRef = old.IPSecSecretRef
		if t.IPSecSecretRef == "" {
			t.IPSecSecretRef = t.Name + "-psk"
		}
	}

	m.mu.RLock()
	tunnels := m.configListLocked()
	m.mu.RUnlock()
	idx := -1
	for i := range tunnels {
		if tunnels[i].Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("tunnel %q is missing from the configuration", name)
	}
	tunnels[idx] = t
	if err := config.ValidateTunnels(tunnels); err != nil {
		return err
	}

	// Any address, credential, or method change requires a clean reconnect.
	m.mu.RLock()
	st := m.states[name]
	wasConnected := st != nil && (st.status == StatusConnected || st.status == StatusConnecting || st.status == StatusFailed)
	m.mu.RUnlock()
	if wasConnected {
		if err := m.disconnectLocked(ctx, name); err != nil {
			return fmt.Errorf("disconnect before edit failed: %w", err)
		}
	}

	changes := map[string]*string{}
	if password != nil && strings.TrimSpace(*password) != "" {
		changes[t.PasswordRef] = password
	}
	if psk != nil && strings.TrimSpace(*psk) != "" {
		changes[t.IPSecSecretRef] = psk
	}
	if len(changes) > 0 {
		if err := m.secrets.SetMany(changes); err != nil {
			return fmt.Errorf("save credentials: %w", err)
		}
	}
	if err := config.SaveTunnels(m.cfg.TunnelsFile, tunnels); err != nil {
		return fmt.Errorf("save tunnels: %w", err)
	}

	m.mu.Lock()
	if st := m.states[name]; st != nil {
		st.cfg = t
	}
	m.mu.Unlock()
	m.log.Info(name, "tunnel updated (%s to %s)", t.Method, t.Server)

	if old.PasswordRef != t.PasswordRef {
		m.dropUnusedSecret(old.PasswordRef, tunnels)
	}
	if old.IPSecSecretRef != t.IPSecSecretRef {
		m.dropUnusedSecret(old.IPSecSecretRef, tunnels)
	}
	return m.reloadLocked(ctx, tunnels)
}

// DeleteTunnel disconnects first, removes routes, deletes generated config,
// and only then removes the definition. Other tunnels are untouched.
func (m *Manager) DeleteTunnel(ctx context.Context, name string) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	old, ok := m.tunnelConfig(name)
	if !ok {
		return fmt.Errorf("tunnel %q is not configured", name)
	}
	m.mu.RLock()
	count := len(m.order)
	m.mu.RUnlock()
	if count <= 1 {
		return errors.New("cannot delete the last tunnel; add another tunnel first")
	}
	if err := m.disconnectLocked(ctx, name); err != nil {
		return fmt.Errorf("refusing to delete: %w", err)
	}
	_ = m.ops.Cleanup(ctx, name)

	m.mu.RLock()
	tunnels := m.configListLocked()
	m.mu.RUnlock()
	out := tunnels[:0]
	for _, t := range tunnels {
		if t.Name != name {
			out = append(out, t)
		}
	}
	if len(out) == len(tunnels) {
		return fmt.Errorf("tunnel %q is missing from the configuration", name)
	}
	if err := config.SaveTunnels(m.cfg.TunnelsFile, out); err != nil {
		return fmt.Errorf("save tunnels: %w", err)
	}
	if err := m.reloadLocked(ctx, out); err != nil {
		m.log.Warn(name, "tunnel deleted but system configuration reload failed: %v", err)
	}

	m.mu.Lock()
	delete(m.states, name)
	for i, n := range m.order {
		if n == name {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	if m.active == name {
		m.active = ""
		m.currentIP = ""
	}
	m.mu.Unlock()

	m.dropUnusedSecret(old.PasswordRef, out)
	m.dropUnusedSecret(old.IPSecSecretRef, out)
	m.log.Info(name, "tunnel deleted")
	return nil
}

func (m *Manager) reloadLocked(ctx context.Context, tunnels []config.Tunnel) error {
	if err := m.ops.Reload(ctx, tunnels); err != nil {
		return fmt.Errorf("configuration saved, but generating or reloading system tunnel configuration failed: %w", err)
	}
	return nil
}

func (m *Manager) configListLocked() []config.Tunnel {
	out := make([]config.Tunnel, 0, len(m.order))
	for _, name := range m.order {
		if st := m.states[name]; st != nil {
			out = append(out, st.cfg)
		}
	}
	return out
}

func (m *Manager) dropUnusedSecret(ref string, tunnels []config.Tunnel) {
	if ref == "" {
		return
	}
	for _, t := range tunnels {
		if t.PasswordRef == ref || t.IPSecSecretRef == ref {
			return
		}
	}
	if err := m.secrets.DeleteRefs(ref); err != nil {
		m.log.Warn("", "could not remove unused credential reference %s: %v", ref, err)
	}
}
