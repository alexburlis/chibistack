package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type runner func(ctx context.Context, step string, args ...string) ([]byte, error)

const nativePath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

// run returns stdout only to the engine. Errors name the step and exit status
// but never carry output: runtime diagnostics may include secrets.
func run(ctx context.Context, step string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Dir = "/"
	c.Env = []string{nativePath, "LANG=C", "HOME=/root"}
	c.WaitDelay = 5 * time.Second
	var out limitedBuffer
	c.Stdout = &out
	if err := c.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("native %s interrupted or timed out", step)
		}
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			return nil, fmt.Errorf("native %s failed (exit %d)", step, exited.ExitCode())
		}
		return nil, fmt.Errorf("native %s could not start", step)
	}
	return out.data, nil
}

type limitedBuffer struct{ data []byte }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.data) < 65536 {
		keep := min(n, 65536-len(b.data))
		b.data = append(b.data, p[:keep]...)
	}
	return n, nil
}

var plainWord = regexp.MustCompile(`^[a-z][a-z-]*$`)

// step names a command by its binary and leading subcommand words, leaving out
// arguments such as image references.
func step(args []string) string {
	words := []string{filepath.Base(args[0])}
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if !plainWord.MatchString(arg) {
			break
		}
		words = append(words, arg)
	}
	return strings.Join(words, " ")
}

func (m *Manager) user(ctx context.Context, c Config, args ...string) ([]byte, error) {
	uid := strconv.Itoa(c.UID)
	prefix := []string{"/usr/sbin/runuser", "-u", c.User, "--", "/usr/bin/env", "-i", "HOME=" + c.Home(), nativePath, "XDG_RUNTIME_DIR=/run/user/" + uid, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + uid + "/bus"}
	return m.exec(ctx, step(args), append(prefix, args...)...)
}

func unit(c Config, slot int) string { return fmt.Sprintf("host-%s-%d", c.App, slot) }

func (m *Manager) quadlets(c Config) string {
	return filepath.Join(m.quadletDir, strconv.Itoa(c.UID))
}

func (m *Manager) stop(ctx context.Context, c Config, slot int) error {
	source := filepath.Join(m.quadlets(c), unit(c, slot)+".container")
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	_, err := m.user(ctx, c, "/usr/bin/systemctl", "--user", "stop", unit(c, slot)+".service")
	return err
}

// stopExcept stops every slot but keep; keep 0 stops both.
func (m *Manager) stopExcept(ctx context.Context, c Config, keep int) error {
	for slot := 1; slot <= 2; slot++ {
		if slot != keep {
			if err := m.stop(ctx, c, slot); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) start(ctx context.Context, c Config, a Accepted) error {
	ref := c.ImageRepo + "@" + a.Release.Digest
	if _, err := m.user(ctx, c, "/usr/bin/podman", "image", "exists", ref); err != nil {
		if _, err = m.user(ctx, c, "/usr/bin/podman", "pull", "--policy=always", ref); err != nil {
			return err
		}
	}
	b, err := m.user(ctx, c, "/usr/bin/podman", "image", "inspect", "--format", "{{json .RepoDigests}}", ref)
	if err != nil {
		return err
	}
	var digests []string
	if json.Unmarshal(b, &digests) != nil {
		return errors.New("invalid image inspection")
	}
	if !slices.Contains(digests, ref) {
		return errors.New("pulled image digest mismatch")
	}
	dir := m.quadlets(c)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err = m.trust(dir); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0755); err != nil {
		return err
	}
	text := quadlet(c, a.Slot, ref)
	p := filepath.Join(dir, unit(c, a.Slot)+".container")
	if err = atomicFile(p, 0644, func(w io.Writer) error { _, err := io.WriteString(w, text); return err }); err != nil {
		return err
	}
	if _, err = m.user(ctx, c, "/usr/bin/systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	_, err = m.user(ctx, c, "/usr/bin/systemctl", "--user", "start", unit(c, a.Slot)+".service")
	return err
}

func quadlet(c Config, slot int, ref string) string {
	text := fmt.Sprintf("[Unit]\nDescription=Chibistack %s slot %d\n[Container]\nImage=%s\nContainerName=%s\nNetwork=%s.network\nPublishPort=%s:%d\nUser=%d:%d\nUserNS=keep-id:uid=%d,gid=%d\nReadOnly=true\nNoNewPrivileges=true\nDropCapability=all\nTmpfs=/tmp:rw,nosuid,nodev,size=64m\nLogDriver=journald\nPodmanArgs=--pull=never\n", c.App, slot, ref, unit(c, slot), c.Network(), c.backend(slot), c.ContainerPort, c.ContainerUID, c.ContainerUID, c.ContainerUID, c.ContainerUID)
	percent, _ := strconv.Atoi(strings.TrimSuffix(c.CPUQuota, "%"))
	text += fmt.Sprintf("PodmanArgs=--memory=%d --memory-swap=%d --cpus=%.2f --pids-limit=256\n", c.MemoryBytes, c.MemoryBytes, float64(percent)/100)
	for _, v := range c.Mounts {
		options := "rw,z"
		if v.ReadOnly {
			options = "ro,z"
		}
		// install-secret labels these root-owned files for containers already.
		if c.secret(v) {
			options = "ro"
		}
		text += fmt.Sprintf("Volume=%s:%s:%s\n", v.Source, v.Target, options)
	}
	return text + fmt.Sprintf("[Service]\nRestart=on-failure\nTimeoutStartSec=90\nTimeoutStopSec=30\nMemoryMax=%d\nMemorySwapMax=0\nCPUQuota=%s\n", c.MemoryBytes, c.CPUQuota)
}

func (m *Manager) waitReady(ctx context.Context, c Config, slot int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.ReadySeconds)*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 2 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		req, err := http.NewRequestWithContext(ctx, "GET", "http://"+c.backend(slot)+c.ReadinessPath, nil)
		if err != nil {
			return err
		}
		r, err := client.Do(req)
		if err == nil {
			r.Body.Close()
			if r.StatusCode >= 200 && r.StatusCode < 300 {
				return nil
			}
		}
		if err = delay(ctx, 250*time.Millisecond); err != nil {
			return errors.New("candidate readiness failed")
		}
	}
}

func delay(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
