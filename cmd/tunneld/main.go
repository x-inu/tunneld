// Command tunneld runs the authenticated tunnel control plane.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"tunneld/internal/config"
	"tunneld/internal/logx"
	"tunneld/internal/store"
	"tunneld/internal/tunnel"
	"tunneld/internal/web"
)

// version can be replaced at build time with:
//
//	go build -ldflags "-X main.version=1.0.0" ./cmd/tunneld
var version = "0.1.0"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if err := hashPasswordCommand(); err != nil {
			fmt.Fprintln(os.Stderr, "tunneld hash-password:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("tunneld", flag.ExitOnError)
	configPath := fs.String("config", "/etc/tunneld/tunneld.yaml", "path to the application configuration")
	demo := fs.Bool("demo", false, "run with the clearly marked simulation backend (never changes routes)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: tunneld [options]\n\nOptions:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nCommands:\n  hash-password   generate a bcrypt administrator password hash\n")
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("tunneld", version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *demo {
		cfg.Demo = true
	}
	if !cfg.Demo && os.Geteuid() != 0 {
		return errors.New("real mode requires root to manage routes, PPP, and strongSwan; use -demo for a safe UI preview")
	}

	tunnels, err := config.LoadTunnels(cfg.TunnelsFile)
	if err != nil {
		return err
	}
	secrets, warnings, err := config.LoadSecrets(cfg.SecretsFile)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Database), 0o700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer st.Close()

	logger := logx.New(st, secrets, cfg.LogLevel)
	for _, warning := range warnings {
		logger.Warn("", "%s", warning)
	}
	if cfg.Demo {
		logger.Warn("", "DEMO MODE: tunnel state is simulated; no routes, interfaces, or PPP processes are touched")
	} else {
		preflight(cfg, logger)
	}

	manager := tunnel.New(cfg, tunnels, st, secrets, logger, version)
	auth := web.NewAuth(cfg)
	server, err := web.NewServer(cfg, manager, auth, st, logger, version)
	if err != nil {
		return err
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := manager.Start(rootCtx); err != nil {
		return fmt.Errorf("start tunnel manager: %w", err)
	}
	go auth.Cleanup(rootCtx)
	go func() {
		prune := func() {
			pruneCtx, cancel := context.WithTimeout(rootCtx, 5*time.Minute)
			defer cancel()
			retention := time.Duration(cfg.Health.LogRetentionDays) * 24 * time.Hour
			if err := st.Prune(pruneCtx, time.Now().UTC().Add(-retention)); err != nil {
				logger.Warn("", "log retention prune failed: %v", err)
			}
		}
		prune()
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-ticker.C:
				prune()
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags|log.LUTC),
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("", "listening on http://%s (demo=%t, version %s)", cfg.Listen, cfg.Demo, version)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		_ = manager.Shutdown(shutdownContext)
		return fmt.Errorf("http server: %w", err)
	case <-rootCtx.Done():
	}

	logger.Info("", "shutdown requested")
	httpCtx, cancelHTTP := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelHTTP()
	if err := httpServer.Shutdown(httpCtx); err != nil {
		logger.Warn("", "HTTP shutdown: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := manager.Shutdown(shutdownCtx); err != nil {
		logger.Warn("", "tunnel shutdown: %v", err)
	}
	logger.Info("", "stopped")
	return nil
}

func preflight(cfg *config.Config, logger *logx.Logger) {
	if _, err := os.Stat("/dev/ppp"); err != nil {
		logger.Warn("", "PPP character device /dev/ppp is unavailable; PPP-based tunnels will fail to connect on this host")
	}
	for name, path := range map[string]string{
		"ip": cfg.Commands.IP, "ping": cfg.Commands.Ping, "curl": cfg.Commands.Curl,
		"pppd": cfg.Commands.Pppd, "xl2tpd": cfg.Commands.Xl2tpd,
		"sstpc": cfg.Commands.Sstpc, "pptp": cfg.Commands.Pptp, "swanctl": cfg.Commands.Swanctl,
	} {
		if info, err := os.Stat(path); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			logger.Warn("", "required command %s (%s) is missing or not executable", name, path)
		}
	}
	for _, dir := range []string{cfg.StateDir, cfg.SwanctlDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			logger.Warn("", "cannot create %s: %v", dir, err)
		}
	}
}

func hashPasswordCommand() error {
	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "New administrator password: ")
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "Confirm password: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if string(first) != string(second) {
			return errors.New("passwords do not match")
		}
		password = string(first)
	} else {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
	}
	hash, err := web.HashPassword(password)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	fmt.Fprintln(os.Stderr, "Add this hash to admin.password_hash in tunneld.yaml. Do not store the plaintext password.")
	return nil
}
