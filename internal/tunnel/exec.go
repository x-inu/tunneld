package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Runner executes external programs without a shell and always with a
// deadline. Arguments are passed separately, never concatenated.
type Runner struct{}

func (Runner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	var stdout, stderr limitedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
	out := stdout.String()
	errOut := stderr.String()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, errOut, fmt.Errorf("%s timed out", shortName(name))
	}
	if err != nil {
		detail := strings.TrimSpace(errOut)
		if detail == "" {
			detail = strings.TrimSpace(out)
		}
		if len(detail) > 600 {
			detail = detail[:600] + "…"
		}
		if detail != "" {
			return out, errOut, fmt.Errorf("%s failed: %s", shortName(name), detail)
		}
		return out, errOut, fmt.Errorf("%s failed: %w", shortName(name), err)
	}
	return out, errOut, nil
}

type limitedBuffer struct {
	buf bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len() < 64*1024 {
		remain := 64*1024 - b.buf.Len()
		if len(p) > remain {
			_, _ = b.buf.Write(p[:remain])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return b.buf.String() }

func shortName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}
