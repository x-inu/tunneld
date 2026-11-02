// Package tunnel implements tunnel lifecycle, health checks, default-route
// switching, and rotation. Tunnels are identified by their configured name,
// never by a PPP interface number.
package tunnel

import (
	"context"
	"time"

	"tunneld/internal/config"
)

type Status string

const (
	StatusDisconnected  Status = "disconnected"
	StatusConnecting    Status = "connecting"
	StatusConnected     Status = "connected"
	StatusDisconnecting Status = "disconnecting"
	StatusFailed        Status = "failed"
)

// Link describes the live kernel state of a connected tunnel.
type Link struct {
	Iface   string    `json:"iface"`
	LocalIP string    `json:"local_ip"`
	PeerIP  string    `json:"peer_ip"`
	Since   time.Time `json:"since"`
}

// Route is the part of a default route needed for switching and rollback.
type Route struct {
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

// Ops is the system boundary. The Linux implementation performs real xl2tpd,
// pppd, strongSwan, and iproute2 operations; demo and test implementations can
// substitute it without touching the manager logic.
type Ops interface {
	Init(ctx context.Context, tunnels []config.Tunnel) error
	Reload(ctx context.Context, tunnels []config.Tunnel) error
	Connect(ctx context.Context, t config.Tunnel) (Link, error)
	Disconnect(ctx context.Context, t config.Tunnel) error
	Link(ctx context.Context, name string) (Link, bool)
	Health(ctx context.Context, t config.Tunnel, l Link, timeout time.Duration) (publicIP string, latency time.Duration, err error)
	Activate(ctx context.Context, t config.Tunnel, l Link) (previous Route, err error)
	VerifyDefault(ctx context.Context) (publicIP string, err error)
	Restore(ctx context.Context, r Route) error
	RestoreOriginal(ctx context.Context) error
	Cleanup(ctx context.Context, name string) error
	DefaultRoute(ctx context.Context) (Route, error)
	Close(ctx context.Context) error
}

// TunnelView is the safe public representation of a tunnel. Credential
// references and values are deliberately absent.
type TunnelView struct {
	Name           string     `json:"name"`
	Method         string     `json:"method"`
	Server         string     `json:"server"`
	Username       string     `json:"username"`
	Enabled        bool       `json:"enabled"`
	Status         Status     `json:"status"`
	Iface          string     `json:"iface"`
	LocalIP        string     `json:"local_ip"`
	PeerIP         string     `json:"peer_ip"`
	PublicIP       string     `json:"public_ip"`
	LatencyMS      int64      `json:"latency_ms"`
	UptimeSeconds  int64      `json:"uptime_seconds"`
	LastCheck      *time.Time `json:"last_check"`
	LastError      string     `json:"last_error"`
	HealthOK       bool       `json:"health_ok"`
	Active         bool       `json:"active"`
	ActiveSince    *time.Time `json:"active_since"`
	FailureStreak  int        `json:"failure_streak"`
	CooldownUntil  *time.Time `json:"cooldown_until"`
	HasPassword    bool       `json:"has_password"`
	HasPSK         bool       `json:"has_psk"`
	UseIPSec       bool       `json:"use_ipsec"`
	SSTPPort       int        `json:"sstp_port"`
	SSTPIgnoreCert bool       `json:"sstp_ignore_cert"`
	SSTPCACert     string     `json:"sstp_ca_cert"`
	PPTPPhone      string     `json:"pptp_phone"`
	MTU            int        `json:"mtu"`
	MRU            int        `json:"mru"`
	RequireMPPE    bool       `json:"require_mpe"`
	Warning        string     `json:"warning"`
}

type RotationView struct {
	Mode             string     `json:"mode"`
	IntervalMinutes  int        `json:"interval_minutes"`
	NextAt           *time.Time `json:"next_at"`
	CountdownSeconds int        `json:"countdown_seconds"`
	Running          bool       `json:"running"`
	LastReason       string     `json:"last_reason"`
	MinInterval      int        `json:"min_interval"`
	MaxInterval      int        `json:"max_interval"`
}

type Counts struct {
	Total     int `json:"total"`
	Connected int `json:"connected"`
	Healthy   int `json:"healthy"`
	Failed    int `json:"failed"`
	Standby   int `json:"standby"`
}

type Snapshot struct {
	Now              time.Time    `json:"now"`
	Version          string       `json:"version"`
	Demo             bool         `json:"demo"`
	Active           string       `json:"active"`
	ActiveMethod     string       `json:"active_method"`
	ActiveServer     string       `json:"active_server"`
	PublicIP         string       `json:"public_ip"`
	PreviousPublicIP string       `json:"previous_public_ip"`
	LastRotationAt   *time.Time   `json:"last_rotation_at"`
	Rotation         RotationView `json:"rotation"`
	Tunnels          []TunnelView `json:"tunnels"`
	Counts           Counts       `json:"counts"`
	UptimeSeconds    int64        `json:"uptime_seconds"`
}
