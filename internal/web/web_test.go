package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tunneld/internal/config"
	"tunneld/internal/logx"
	"tunneld/internal/store"
	"tunneld/internal/tunnel"
)

const (
	testAdminName   = "admin"
	testPassword    = "correct-horse-battery-staple"
	testSecretOne   = "alpha-password-value-SECRET"
	testSecretTwo   = "alpha-psk-value-SECRET"
	testSecretThree = "beta-password-value-SECRET"
)

type webFixture struct {
	cfg     *config.Config
	secrets *config.SecretStore
	store   *store.Store
	manager *tunnel.Manager
	server  *Server
	ts      *httptest.Server
}

func newWebFixture(t *testing.T) *webFixture {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Demo = true
	cfg.Database = filepath.Join(dir, "tunneld.db")
	cfg.TunnelsFile = filepath.Join(dir, "tunnels.yaml")
	cfg.SecretsFile = filepath.Join(dir, "secrets.yaml")
	cfg.StateDir = filepath.Join(dir, "run")
	cfg.SwanctlDir = filepath.Join(dir, "swanctl")
	cfg.LogLevel = "error"

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}
	cfg.Admin.Username = testAdminName
	cfg.Admin.PasswordHash = string(hash)

	secrets, _, err := config.LoadSecrets(cfg.SecretsFile)
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	for ref, value := range map[string]string{
		"alpha-password": testSecretOne,
		"alpha-psk":      testSecretTwo,
		"beta-password":  testSecretThree,
	} {
		if err := secrets.Set(ref, value); err != nil {
			t.Fatalf("set secret %s: %v", ref, err)
		}
	}

	st, err := store.Open(cfg.Database)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	logger := logx.New(st, secrets, cfg.LogLevel)
	tunnels := []config.Tunnel{
		{
			Name: "alpha", Method: config.MethodL2TP, Server: "alpha.example.net",
			Username: "user-one", PasswordRef: "alpha-password", UseIPSec: true,
			IPSecSecretRef: "alpha-psk", MTU: 1400, MRU: 1400, Enabled: true,
		},
		{
			Name: "beta", Method: config.MethodSSTP, Server: "beta.example.net",
			Username: "user-two", PasswordRef: "beta-password", SSTPPort: 443,
			MTU: 1400, MRU: 1400, Enabled: true,
		},
	}
	manager := tunnel.New(&cfg, tunnels, st, secrets, logger, "test-version")
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("start manager: %v", err)
	}
	// Start restores enabled tunnels asynchronously; wait for a deterministic
	// starting point before exercising the API.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if manager.Snapshot().Counts.Connected == len(tunnels) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("demo tunnels did not connect: %+v", manager.Snapshot().Counts)
		}
		time.Sleep(10 * time.Millisecond)
	}
	auth := NewAuth(&cfg)
	server, err := NewServer(&cfg, manager, auth, st, logger, "test-version")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(server.Handler())

	f := &webFixture{cfg: &cfg, secrets: secrets, store: st, manager: manager, server: server, ts: ts}
	t.Cleanup(func() {
		ts.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Shutdown(ctx)
		_ = st.Close()
	})
	return f
}

type apiResponse struct {
	status  int
	body    []byte
	header  http.Header
	cookies []*http.Cookie
}

func doRequest(t *testing.T, client *http.Client, method, url string, payload any, csrf string) apiResponse {
	t.Helper()
	var body *strings.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		body = strings.NewReader(string(data))
	} else {
		body = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return apiResponse{status: resp.StatusCode, body: data, header: resp.Header.Clone(), cookies: resp.Cookies()}
}

func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &http.Client{Jar: jar}
}

func (f *webFixture) login(t *testing.T, client *http.Client) string {
	t.Helper()
	resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/login", map[string]string{
		"username": testAdminName, "password": testPassword,
	}, "")
	if resp.status != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", resp.status, resp.body)
	}
	var out struct {
		Username string `json:"username"`
		CSRF     string `json:"csrf_token"`
		Demo     bool   `json:"demo"`
	}
	if err := json.Unmarshal(resp.body, &out); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if out.Username != testAdminName || out.CSRF == "" || !out.Demo {
		t.Fatalf("unexpected login response: %s", resp.body)
	}
	var found bool
	for _, c := range resp.cookies {
		if c.Name != sessionCookie {
			continue
		}
		found = true
		if !c.HttpOnly {
			t.Error("session cookie must be HttpOnly")
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Error("session cookie must use SameSite=Strict")
		}
		if c.Path != "/" {
			t.Errorf("session cookie path = %q, want /", c.Path)
		}
		if c.Secure {
			t.Error("plain HTTP test cookie must not be Secure")
		}
	}
	if !found {
		t.Fatal("login response did not set a session cookie")
	}
	return out.CSRF
}

func TestUnauthenticatedAccessAndSecurityHeaders(t *testing.T) {
	f := newWebFixture(t)

	resp := doRequest(t, nil, http.MethodGet, f.ts.URL+"/api/state", nil, "")
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated state status = %d, want 401", resp.status)
	}
	if got := resp.header.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Errorf("CSP missing or weak: %q", got)
	}
	for name, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := resp.header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp = doRequest(t, noRedirect, http.MethodGet, f.ts.URL+"/", nil, "")
	if resp.status != http.StatusSeeOther || resp.header.Get("Location") != "/login" {
		t.Fatalf("unauthenticated index = %d %q, want 303 /login", resp.status, resp.header.Get("Location"))
	}

	resp = doRequest(t, nil, http.MethodGet, f.ts.URL+"/login", nil, "")
	if resp.status != http.StatusOK {
		t.Fatalf("login page status = %d", resp.status)
	}
	if !strings.Contains(strings.ToLower(string(resp.body)), "sign in") {
		t.Error("login page is missing its English sign-in heading")
	}
}

func TestLoginCSRFAndRotation(t *testing.T) {
	f := newWebFixture(t)
	client := newBrowser(t)

	bad := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/login", map[string]string{
		"username": testAdminName, "password": "wrong-password",
	}, "")
	if bad.status != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", bad.status)
	}

	csrf := f.login(t, client)

	sess := doRequest(t, client, http.MethodGet, f.ts.URL+"/api/session", nil, "")
	if sess.status != http.StatusOK || !strings.Contains(string(sess.body), `"csrf_token"`) {
		t.Fatalf("session response: %d %s", sess.status, sess.body)
	}

	if resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/rotate", nil, ""); resp.status != http.StatusForbidden {
		t.Fatalf("rotate without CSRF = %d, want 403", resp.status)
	}
	if resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/rotate", nil, "wrong-token"); resp.status != http.StatusForbidden {
		t.Fatalf("rotate with wrong CSRF = %d, want 403", resp.status)
	}

	for _, name := range []string{"alpha", "beta"} {
		resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/tunnels/"+name+"/connect", nil, csrf)
		if resp.status != http.StatusOK {
			t.Fatalf("connect %s = %d: %s", name, resp.status, resp.body)
		}
	}
	if resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/tunnels/alpha/activate", nil, csrf); resp.status != http.StatusOK {
		t.Fatalf("activate alpha = %d: %s", resp.status, resp.body)
	}

	stateResp := doRequest(t, client, http.MethodGet, f.ts.URL+"/api/state", nil, "")
	var before tunnel.Snapshot
	if err := json.Unmarshal(stateResp.body, &before); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if before.Active != "alpha" || before.PublicIP != "203.0.113.10" {
		t.Fatalf("unexpected state before rotation: active=%q public_ip=%q", before.Active, before.PublicIP)
	}

	rotated := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/rotate", nil, csrf)
	if rotated.status != http.StatusOK {
		t.Fatalf("rotation = %d: %s", rotated.status, rotated.body)
	}
	afterResp := doRequest(t, client, http.MethodGet, f.ts.URL+"/api/state", nil, "")
	var after tunnel.Snapshot
	if err := json.Unmarshal(afterResp.body, &after); err != nil {
		t.Fatalf("decode state after rotation: %v", err)
	}
	if after.Active != "beta" {
		t.Fatalf("rotation active = %q, want beta", after.Active)
	}
	if after.PublicIP == "" || after.PublicIP == before.PublicIP {
		t.Fatalf("rotation public IP did not change: before=%q after=%q", before.PublicIP, after.PublicIP)
	}

	for _, endpoint := range []string{"/api/history", "/api/logs", "/api/audit"} {
		resp := doRequest(t, client, http.MethodGet, f.ts.URL+endpoint, nil, "")
		if resp.status != http.StatusOK {
			t.Fatalf("%s status = %d", endpoint, resp.status)
		}
		for _, secret := range []string{testSecretOne, testSecretTwo, testSecretThree} {
			if strings.Contains(string(resp.body), secret) {
				t.Fatalf("%s leaked a credential value", endpoint)
			}
		}
	}

	if resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/logout", nil, csrf); resp.status != http.StatusOK {
		t.Fatalf("logout = %d: %s", resp.status, resp.body)
	}
	if resp := doRequest(t, client, http.MethodGet, f.ts.URL+"/api/state", nil, ""); resp.status != http.StatusUnauthorized {
		t.Fatalf("state after logout = %d, want 401", resp.status)
	}
}

func TestAPIResponsesNeverExposeSecretReferencesOrValues(t *testing.T) {
	f := newWebFixture(t)
	client := newBrowser(t)
	csrf := f.login(t, client)

	for _, target := range []string{"/api/state", "/api/session"} {
		resp := doRequest(t, client, http.MethodGet, f.ts.URL+target, nil, "")
		if resp.status != http.StatusOK {
			t.Fatalf("%s = %d: %s", target, resp.status, resp.body)
		}
		text := string(resp.body)
		for _, forbidden := range []string{"password_ref", "ipsec_secret_ref", testSecretOne, testSecretTwo, testSecretThree} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s exposed %q", target, forbidden)
			}
		}
	}
	state := doRequest(t, client, http.MethodGet, f.ts.URL+"/api/state", nil, "")
	if !strings.Contains(string(state.body), `"has_password":true`) {
		t.Fatalf("state is missing credential presence flags: %s", state.body)
	}

	// A rejected action must not leak credentials through the error path.
	resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/tunnels/missing/connect", nil, csrf)
	if resp.status != http.StatusConflict {
		t.Fatalf("connect missing tunnel = %d, want 409", resp.status)
	}
	for _, secret := range []string{testSecretOne, testSecretTwo, testSecretThree} {
		if strings.Contains(string(resp.body), secret) {
			t.Fatalf("error response leaked a credential value")
		}
	}
}

func TestTunnelCRUD(t *testing.T) {
	f := newWebFixture(t)
	client := newBrowser(t)
	csrf := f.login(t, client)

	add := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/tunnels", map[string]any{
		"name": "gamma", "method": "l2tp", "server": "gamma.example.net",
		"username": "gamma-user", "password": "gamma-password-SECRET",
		"mtu": 1400, "mru": 1400,
	}, csrf)
	if add.status != http.StatusCreated {
		t.Fatalf("add tunnel = %d: %s", add.status, add.body)
	}
	state := doRequest(t, client, http.MethodGet, f.ts.URL+"/api/state", nil, "")
	if !strings.Contains(string(state.body), `"name":"gamma"`) {
		t.Fatalf("new tunnel is missing from state: %s", state.body)
	}
	if strings.Contains(string(state.body), "gamma-password-SECRET") {
		t.Fatal("state leaked the new tunnel password")
	}

	update := doRequest(t, client, http.MethodPut, f.ts.URL+"/api/tunnels/gamma", map[string]any{
		"name": "gamma", "method": "sstp", "server": "gamma.example.net",
		"username": "gamma-user", "sstp_port": 443, "mtu": 1400, "mru": 1400,
	}, csrf)
	if update.status != http.StatusOK {
		t.Fatalf("update tunnel = %d: %s", update.status, update.body)
	}
	state = doRequest(t, client, http.MethodGet, f.ts.URL+"/api/state", nil, "")
	if !strings.Contains(string(state.body), `"name":"gamma","method":"sstp"`) {
		t.Fatalf("updated method is missing from state: %s", state.body)
	}

	remove := doRequest(t, client, http.MethodDelete, f.ts.URL+"/api/tunnels/gamma", nil, csrf)
	if remove.status != http.StatusOK {
		t.Fatalf("delete tunnel = %d: %s", remove.status, remove.body)
	}
	state = doRequest(t, client, http.MethodGet, f.ts.URL+"/api/state", nil, "")
	if strings.Contains(string(state.body), `"name":"gamma"`) {
		t.Fatal("deleted tunnel is still present in state")
	}
}

func TestLoginRateLimit(t *testing.T) {
	f := newWebFixture(t)
	client := newBrowser(t)
	for i := 0; i < 5; i++ {
		resp := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/login", map[string]string{
			"username": testAdminName, "password": fmt.Sprintf("wrong-%d", i),
		}, "")
		if resp.status != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, resp.status)
		}
	}
	blocked := doRequest(t, client, http.MethodPost, f.ts.URL+"/api/login", map[string]string{
		"username": testAdminName, "password": testPassword,
	}, "")
	if blocked.status != http.StatusTooManyRequests {
		t.Fatalf("blocked login = %d, want 429", blocked.status)
	}
	if blocked.header.Get("Retry-After") == "" {
		t.Fatal("rate-limited response is missing Retry-After")
	}
	if strings.Contains(string(blocked.body), testPassword) {
		t.Fatal("rate-limit response leaked the submitted password")
	}
}

func TestProxyAwareSecureCookieAndHTTPSHeaders(t *testing.T) {
	f := newWebFixture(t)
	client := newBrowser(t)
	req, err := http.NewRequest(http.MethodPost, f.ts.URL+"/api/login", strings.NewReader(
		`{"username":"`+testAdminName+`","password":"`+testPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy login = %d", resp.StatusCode)
	}
	var secureCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			secureCookie = c.Secure
		}
	}
	if !secureCookie {
		t.Fatal("cookie must be Secure behind a trusted HTTPS proxy")
	}
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Fatal("HSTS is missing on a trusted HTTPS proxy request")
	}
}

func TestSSEStreamCarriesStateWithoutSecrets(t *testing.T) {
	f := newWebFixture(t)
	client := newBrowser(t)
	f.login(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.ts.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("events content type = %q", got)
	}

	scanner := bufio.NewScanner(resp.Body)
	var data string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if data == "" {
		t.Fatal("SSE stream did not deliver a state event")
	}
	if !strings.Contains(data, `"tunnels"`) {
		t.Fatalf("unexpected SSE payload: %s", data)
	}
	for _, secret := range []string{testSecretOne, testSecretTwo, testSecretThree} {
		if strings.Contains(data, secret) {
			t.Fatal("SSE payload leaked a credential value")
		}
	}
}
