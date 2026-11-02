package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunneld/internal/config"
	"tunneld/internal/logx"
	"tunneld/internal/store"
)

func testSecrets(t *testing.T) (*config.Config, *config.SecretStore) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.StateDir = filepath.Join(dir, "run")
	cfg.SwanctlDir = filepath.Join(dir, "swanctl")
	cfg.TunnelsFile = filepath.Join(dir, "tunnels.yaml")
	cfg.SecretsFile = filepath.Join(dir, "secrets.yaml")
	secrets, _, err := config.LoadSecrets(cfg.SecretsFile)
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	return &cfg, secrets
}

func TestGeneratePPPAlwaysDisablesDefaultRoute(t *testing.T) {
	cfg, secrets := testSecrets(t)
	password := "p@ss word\"quoted"
	if err := secrets.Set("pw", password); err != nil {
		t.Fatal(err)
	}
	tunnel := config.Tunnel{
		Name: "edge-one", Method: config.MethodL2TP, Server: "vpn.example.net",
		Username: "user", PasswordRef: "pw", MTU: 1400, MRU: 1400, Enabled: true,
	}
	content, err := generatePPP(cfg, secrets, tunnel)
	if err != nil {
		t.Fatalf("generate PPP: %v", err)
	}
	if !strings.Contains(content, "\nnodefaultroute\n") {
		t.Fatal("generated PPP options must contain nodefaultroute")
	}
	if strings.Contains(content, "\ndefaultroute\n") {
		t.Fatal("generated PPP options must never set defaultroute")
	}
	if !strings.Contains(content, "hide-password") {
		t.Fatal("hide-password is missing")
	}
	if !strings.Contains(content, "ipparam \"edge-one\"") {
		t.Fatal("ipparam must carry the tunnel name")
	}
	if !strings.Contains(content, `password "p@ss word\"quoted"`) {
		t.Fatal("password was not escaped for pppd")
	}
	if !strings.Contains(content, "noccp") {
		t.Fatal("L2TP options should disable CCP")
	}

	sstp := tunnel
	sstp.Method = config.MethodSSTP
	sstp.SSTPPort = 443
	sstp.SSTPIgnoreCert = true
	sstpContent, err := generatePPP(cfg, secrets, sstp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sstpContent, "pty ") || !strings.Contains(sstpContent, "--nolaunchpppd") || !strings.Contains(sstpContent, "--cert-warn") {
		t.Fatalf("unexpected SSTP pty options: %s", sstpContent)
	}

	pptp := tunnel
	pptp.Method = config.MethodPPTP
	pptp.RequireMPPE = true
	pptpContent, err := generatePPP(cfg, secrets, pptp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pptpContent, "--nohostroute") || !strings.Contains(pptpContent, "require-mppe-128") {
		t.Fatalf("unexpected PPTP options: %s", pptpContent)
	}
}

func TestGenerateSwanctlTransportMode(t *testing.T) {
	cfg, secrets := testSecrets(t)
	psk := "long-pre-shared-key"
	if err := secrets.Set("psk", psk); err != nil {
		t.Fatal(err)
	}
	tunnel := config.Tunnel{
		Name: "ipsec-one", Method: config.MethodL2TP, Server: "vpn.example.net",
		Username: "user", PasswordRef: "pw", UseIPSec: true, IPSecSecretRef: "psk",
		MTU: 1400, MRU: 1400, Enabled: true,
	}
	content, err := generateSwanctl(cfg, secrets, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version = 1", "mode = transport", "remote_addrs = vpn.example.net", `secret = "long-pre-shared-key"`} {
		if !strings.Contains(content, want) {
			t.Fatalf("swanctl config missing %q:\n%s", want, content)
		}
	}
	if _, ok := secrets.Get("missing"); ok {
		t.Fatal("unexpected secret")
	}
}

func TestWriteGeneratedFilesSkipsMissingCredential(t *testing.T) {
	cfg, secrets := testSecrets(t)
	password := "stored-password"
	if err := secrets.Set("one-password", password); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ops := NewLinuxOps(cfg, secrets, logx.New(st, secrets, "error"))
	tunnels := []config.Tunnel{
		{Name: "one", Method: config.MethodL2TP, Server: "one.example.net", Username: "u", PasswordRef: "one-password", MTU: 1400, MRU: 1400, Enabled: true},
		{Name: "two", Method: config.MethodSSTP, Server: "two.example.net", Username: "u", PasswordRef: "two-password", SSTPPort: 443, MTU: 1400, MRU: 1400, Enabled: true},
	}
	if err := ops.writeGeneratedFiles(tunnels); err != nil {
		t.Fatalf("write generated files: %v", err)
	}
	one := filepath.Join(cfg.StateDir, "ppp", "one.options")
	info, err := os.Stat(one)
	if err != nil {
		t.Fatalf("expected generated options for one: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("PPP options mode = %o, want 0600", info.Mode().Perm())
	}
	content, err := os.ReadFile(one)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "nodefaultroute") {
		t.Fatal("nodefaultroute missing from generated file")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "ppp", "two.options")); !os.IsNotExist(err) {
		t.Fatalf("options for a tunnel without a credential should not exist: %v", err)
	}
}

func TestXL2TPDConfigUsesTunnelNames(t *testing.T) {
	cfg, _ := testSecrets(t)
	tunnels := []config.Tunnel{
		{Name: "alpha", Method: config.MethodL2TP, Server: "a.example.net", Enabled: true},
		{Name: "beta", Method: config.MethodSSTP, Server: "b.example.net", SSTPPort: 443, Enabled: true},
	}
	content := generateXL2TPD(cfg, tunnels)
	if !strings.Contains(content, "[lac alpha]") {
		t.Fatal("L2TP tunnel name missing from xl2tpd config")
	}
	if strings.Contains(content, "[lac beta]") {
		t.Fatal("SSTP tunnel must not appear as an L2TP LAC")
	}
	if !strings.Contains(content, pppOptionsPath(cfg.StateDir, "alpha")) {
		t.Fatal("pppoptfile path is missing")
	}
}
