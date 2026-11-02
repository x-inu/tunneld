package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	refRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	usernameRe = regexp.MustCompile(`^[A-Za-z0-9_.@+-]{1,128}$`)
	phoneRe    = regexp.MustCompile(`^[A-Za-z0-9_.+*#-]{0,64}$`)
	labelRe    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// NormalizeTunnel fills defaults and trims whitespace. It does not validate.
func NormalizeTunnel(t *Tunnel) {
	t.Name = strings.TrimSpace(t.Name)
	t.Server = strings.TrimSpace(t.Server)
	t.Username = strings.TrimSpace(t.Username)
	t.PasswordRef = strings.TrimSpace(t.PasswordRef)
	t.IPSecSecretRef = strings.TrimSpace(t.IPSecSecretRef)
	t.SSTPCACert = strings.TrimSpace(t.SSTPCACert)
	t.PPTPPhone = strings.TrimSpace(t.PPTPPhone)
	if t.MTU == 0 {
		t.MTU = 1400
	}
	if t.MRU == 0 {
		t.MRU = 1400
	}
	if t.Method == MethodSSTP && t.SSTPPort == 0 {
		t.SSTPPort = 443
	}
	if t.Method != MethodSSTP {
		t.SSTPPort = 0
	}
}

// ValidateTunnels validates the whole list, including duplicate names.
func ValidateTunnels(tunnels []Tunnel) error {
	if len(tunnels) == 0 {
		return errors.New("at least one tunnel must be configured")
	}
	if len(tunnels) > 200 {
		return errors.New("a maximum of 200 tunnels is supported")
	}
	var errs []error
	seen := map[string]int{}
	for i := range tunnels {
		t := tunnels[i]
		if err := ValidateTunnel(&t, i); err != nil {
			errs = append(errs, err)
		}
		key := strings.ToLower(t.Name)
		if prev, ok := seen[key]; ok {
			errs = append(errs, fmt.Errorf("tunnels[%d]: duplicate tunnel name %q (also at index %d)", i, t.Name, prev))
		} else {
			seen[key] = i
		}
	}
	return errors.Join(errs...)
}

// ValidateTunnel validates one tunnel. index is used only in error messages.
func ValidateTunnel(t *Tunnel, index int) error {
	prefix := fmt.Sprintf("tunnels[%d]", index)
	if t.Name == "" {
		prefix += " (name unknown)"
	} else {
		prefix += fmt.Sprintf(" (%s)", t.Name)
	}
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", prefix, fmt.Sprintf(format, args...)))
	}
	if !nameRe.MatchString(t.Name) {
		add("name must be 1-32 characters, start with a letter or digit, and contain only letters, digits, '-' or '_'")
	}
	switch t.Method {
	case MethodL2TP, MethodSSTP, MethodPPTP:
	default:
		add("method must be one of l2tp, sstp, pptp")
	}
	if !validHost(t.Server) {
		add("server must be a valid IPv4 address or hostname (no scheme, path, spaces, or shell characters)")
	}
	if !usernameRe.MatchString(t.Username) {
		add("username must be 1-128 characters and contain only letters, digits, '.', '_', '@', '+', or '-'")
	}
	if t.PasswordRef == "" {
		add("password_ref is required")
	} else if !refRe.MatchString(t.PasswordRef) {
		add("password_ref contains unsafe characters")
	}
	if t.MTU < 576 || t.MTU > 1500 {
		add("mtu must be between 576 and 1500")
	}
	if t.MRU < 576 || t.MRU > 1500 {
		add("mru must be between 576 and 1500")
	}
	switch t.Method {
	case MethodL2TP:
		if t.UseIPSec {
			if t.IPSecSecretRef == "" {
				add("ipsec_secret_ref is required when use_ipsec is true")
			} else if !refRe.MatchString(t.IPSecSecretRef) {
				add("ipsec_secret_ref contains unsafe characters")
			}
		}
		if t.SSTPPort != 0 || t.SSTPIgnoreCert || t.SSTPCACert != "" || t.PPTPPhone != "" {
			add("SSTP/PPTP-only fields are set on an L2TP tunnel")
		}
	case MethodSSTP:
		if t.SSTPPort < 1 || t.SSTPPort > 65535 {
			add("sstp_port must be between 1 and 65535")
		}
		if t.SSTPCACert != "" && !filepath.IsAbs(t.SSTPCACert) {
			add("sstp_ca_cert must be an absolute path")
		}
		if t.UseIPSec || t.IPSecSecretRef != "" || t.PPTPPhone != "" {
			add("L2TP/PPTP-only fields are set on an SSTP tunnel")
		}
	case MethodPPTP:
		if t.PPTPPhone != "" && !phoneRe.MatchString(t.PPTPPhone) {
			add("pptp_phone contains unsafe characters")
		}
		if t.UseIPSec || t.IPSecSecretRef != "" || t.SSTPPort != 0 || t.SSTPIgnoreCert || t.SSTPCACert != "" {
			add("L2TP/SSTP-only fields are set on a PPTP tunnel")
		}
	}
	return errors.Join(errs...)
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.ContainsAny(host, " \t\r\n/\\'\"`$;&|<>(){}[]*?!#%") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil
	}
	host = strings.TrimSuffix(host, ".")
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		// Single-label names are common in labs; accept them if the label is valid.
		return labelRe.MatchString(labels[0])
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}
