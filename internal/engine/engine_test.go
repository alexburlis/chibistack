package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"minimal.host/platform/internal/protocol"
)

type fixture struct {
	t     *testing.T
	m     *Manager
	c     Config
	hash  string
	live  int
	calls []string
}

func setup(t *testing.T, mode string) *fixture {
	t.Helper()
	dir := t.TempDir()
	m := New()
	m.configDir = filepath.Join(dir, "config")
	m.stateDir = filepath.Join(dir, "state")
	m.approvalDir = filepath.Join(dir, "approved")
	m.quadletDir = filepath.Join(dir, "quadlets")
	m.lockPath = filepath.Join(dir, "lifecycle.lock")
	m.trust = func(string) error { return nil }
	m.lookupUser = func(name string) (string, error) {
		if name != "app-demo" {
			return "", errors.New("unknown fixture identity")
		}
		return "2001", nil
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{App: "demo", User: "app-demo", UID: 2001, ImageRepo: "ghcr.io/example/demo", Hostname: "demo.example.test", Ports: [2]int{18081, 18082}, ContainerPort: 8080, ContainerUID: 65532, ReadinessPath: "/ready", Mode: mode, MemoryBytes: 128 << 20, CPUQuota: "100%", ReadySeconds: 1, DrainSeconds: 1, GitHub: GitHub{Repo: "example/demo", Branch: "main", Environment: "production", CreatorID: 42, WorkflowPath: ".github/workflows/release.yml", WorkflowSHA256: strings.Repeat("c", 64), SigningPublicKey: base64.StdEncoding.EncodeToString(pub)}}
	b, _ := json.Marshal(c)
	if err := os.MkdirAll(m.configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.configDir, "demo.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	_, hash, err := ReadConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, m: m, c: c, hash: hash}
	m.exec = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		f.calls = append(f.calls, strings.Join(args, " "))
		if slices.Contains(args, "inspect") {
			return json.Marshal([]string{c.ImageRepo + "@sha256:" + strings.Repeat("a", 64)})
		}
		return nil, nil
	}
	m.ready = func(context.Context, Config, int) error { return nil }
	m.switchRoute = func(_ context.Context, _ Config, slot int) error { f.live = slot; return nil }
	m.routeSlot = func(context.Context, Config) (int, error) { return f.live, nil }
	m.drain = func(context.Context, time.Duration) error { return nil }
	return f
}
func (f *fixture) approve(id string, n int64, expected string) Release {
	f.t.Helper()
	r := Release{ID: id, App: "demo", SHA: strings.Repeat("b", 40), Digest: "sha256:" + strings.Repeat("a", 64), ConfigSHA256: f.hash, RunID: n, ExpectedCurrent: expected}
	if err := atomicJSON(filepath.Join(f.m.approvalDir, "demo", id+".json"), r); err != nil {
		f.t.Fatal(err)
	}
	return r
}
func (f *fixture) op(op, id string) error {
	_, err := f.m.Handle(context.Background(), protocol.Request{Op: op, App: "demo", Release: id})
	return err
}
func (f *fixture) state() State {
	f.t.Helper()
	s, err := f.m.state("demo")
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}
func TestDeployDuplicateAndRollbackHold(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	n := len(f.calls)
	if err := f.op("deploy", "r-one"); err != nil || len(f.calls) != n {
		t.Fatal("duplicate was not a no-op", err)
	}
	f.approve("r-two", 2, "r-one")
	if err := f.op("deploy", "r-two"); err != nil {
		t.Fatal(err)
	}
	if err := f.op("rollback", ""); err != nil {
		t.Fatal(err)
	}
	s := f.state()
	if !s.Hold || s.Current.Release.ID != "r-one" || f.live != 1 {
		t.Fatal("rollback not held", s)
	}
	f.approve("r-three", 3, "r-one")
	if err := f.op("deploy", "r-three"); err == nil {
		t.Fatal("held automatic release admitted")
	}
	if err := f.m.Resume("demo", 3); err != nil {
		t.Fatal(err)
	}
	if err := f.op("deploy", "r-three"); err == nil {
		t.Fatal("resume barrier did not supersede old request")
	}
}
func TestFailedCandidatePreservesAcceptedRoute(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	f.approve("r-two", 2, "r-one")
	f.m.ready = func(context.Context, Config, int) error { return errors.New("unready") }
	if err := f.op("deploy", "r-two"); err == nil {
		t.Fatal("unready admitted")
	}
	s := f.state()
	if !s.Hold || s.Pending != nil || f.live != 1 || s.Current.Release.ID != "r-one" {
		t.Fatal("failed candidate replaced accepted route", s)
	}
}
func TestInterruptedPromotionRestoresReceiptAndHolds(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	f.approve("r-two", 2, "r-one")
	f.m.switchRoute = func(_ context.Context, _ Config, slot int) error {
		f.live = slot
		return errors.New("lost proxy reply")
	}
	if err := f.op("deploy", "r-two"); err == nil {
		t.Fatal("lost proxy reply accepted")
	}
	if f.live != 2 || f.state().Pending == nil {
		t.Fatal("fixture did not witness interrupted promotion")
	}
	f.m.switchRoute = func(_ context.Context, _ Config, slot int) error { f.live = slot; return nil }
	if err := f.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := f.state()
	if f.live != 1 || s.Pending != nil || !s.Hold || s.Current.Release.ID != "r-one" {
		t.Fatal("unsafe interrupted reconciliation", s)
	}
}
func TestSingletonRecoveryStopsCandidateFirst(t *testing.T) {
	f := setup(t, "singleton")
	r := f.approve("r-one", 1, "")
	candidate := f.approve("r-two", 2, "r-one")
	s := State{Current: &Accepted{r, 1}, Pending: &Accepted{candidate, 2}, HighWater: 2}
	if err := f.m.save("demo", &s, "interrupted"); err != nil {
		t.Fatal(err)
	}
	f.live = 2
	dir := filepath.Join(f.m.quadletDir, "2001")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host-demo-1.container", "host-demo-2.container"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[Container]\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	stop, start := -1, -1
	for n, c := range f.calls {
		if strings.Contains(c, "stop host-demo-2.service") && stop < 0 {
			stop = n
		}
		if strings.Contains(c, "start host-demo-1.service") && start < 0 {
			start = n
		}
	}
	if stop < 0 || start < 0 || stop >= start {
		t.Fatal("singleton writers could overlap", f.calls)
	}
	file := filepath.Join(f.m.quadletDir, "2001", "host-demo-1.container")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "[Install]") || strings.Contains(string(b), ":Z") {
		t.Fatal("stale auto-start or exclusive-label overlap", string(b))
	}
}
func TestAdmissionBoundariesAndCorruptState(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "other")
	if err := f.op("deploy", "r-one"); err == nil {
		t.Fatal("stale expected current admitted")
	}
	if len(f.calls) != 0 {
		t.Fatal("stale request had effects")
	}
	if err := f.op("deploy", "not-approved"); err == nil {
		t.Fatal("unapproved admitted")
	}
	if _, err := f.m.Handle(context.Background(), protocol.Request{Op: "shell", App: "demo"}); err == nil {
		t.Fatal("shell admitted")
	}
	if err := os.MkdirAll(f.m.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.m.stateDir, "demo.json"), []byte(`{"current":`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.op("deploy", "r-one"); err == nil {
		t.Fatal("corrupt state admitted")
	}
}
func TestLockAndConfigMismatch(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	held, err := f.m.lock()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.op("deploy", "r-one"); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatal("lock missing", err)
	}
	held.release()
	f.hash = strings.Repeat("f", 64)
	f.approve("r-two", 2, "")
	if err = f.op("deploy", "r-two"); err == nil {
		t.Fatal("wrong configuration admitted")
	}
}
func TestDigestMismatchNeverPromotes(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	f.m.exec = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if slices.Contains(args, "inspect") {
			return []byte(`["ghcr.io/example/demo@sha256:bad"]`), nil
		}
		return nil, nil
	}
	if err := f.op("deploy", "r-one"); err == nil {
		t.Fatal("wrong digest admitted")
	}
	if f.live != 0 || !f.state().Hold {
		t.Fatal("digest mismatch promoted")
	}
}
func TestConfigRejectsInjectionAndUnsafeMounts(t *testing.T) {
	f := setup(t, "overlap")
	for _, mutate := range []func(*Config){func(c *Config) { c.User = "root\nExecStart=/bin/sh" }, func(c *Config) { c.ReadinessPath = "/x\r\nHeader:x" }, func(c *Config) { c.ImageRepo = "ghcr.io/example/app:latest" }, func(c *Config) { c.Mounts = []Mount{{Source: "/etc/shadow", Target: "/secret"}} }, func(c *Config) { c.Ports = [2]int{17999, 18082} }, func(c *Config) { c.Ports = [2]int{18081, 19000} }, func(c *Config) { c.Ports = [2]int{18081, 18081} }} {
		c := f.c
		mutate(&c)
		if c.validate() == nil {
			t.Fatal("unsafe configuration accepted", c)
		}
	}
}

func TestRegistryRepositoryGrammar(t *testing.T) {
	for _, s := range []string{"ghcr.io/owner/app", "localhost:5000/demo", "registry.example:5443/team/app", "[::1]:5000/demo"} {
		if !validImageRepo(s) {
			t.Fatal("valid TLS registry rejected", s)
		}
	}
	for _, s := range []string{"ghcr.io/owner/app:latest", "localhost:0/app", "localhost:65536/app", "localhost:/app", "https://ghcr.io/owner/app", "user@registry.example/app", "registry.example/../app", "registry.example/app?query=x", "registry.example/app#fragment"} {
		if validImageRepo(s) {
			t.Fatal("invalid registry accepted", s)
		}
	}
}
func TestRouteReceiptMismatchCreatesHold(t *testing.T) {
	f := setup(t, "overlap")
	r := f.approve("r-one", 1, "")
	s := State{Current: &Accepted{r, 1}, HighWater: 1}
	if err := f.m.save("demo", &s, "accepted"); err != nil {
		t.Fatal(err)
	}
	f.live = 2
	if err := f.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	s = f.state()
	if !s.Hold || f.live != 1 || s.Current.Release.ID != "r-one" {
		t.Fatal("route drift not held/restored", s)
	}
}

func TestReconcileStopsOnlyUnacceptedSlots(t *testing.T) {
	for _, mode := range []string{"overlap", "singleton"} {
		for _, current := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%s-current-%d", mode, current), func(t *testing.T) {
				f := setup(t, mode)
				s := State{}
				if current != 0 {
					s.Current, s.HighWater = &Accepted{f.approve("r-one", 1, ""), current}, 1
				}
				if err := f.m.save("demo", &s, "accepted"); err != nil {
					t.Fatal(err)
				}
				f.live = current
				dir := filepath.Join(f.m.quadletDir, "2001")
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"host-demo-1.container", "host-demo-2.container"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte("[Container]\n"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.m.Reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
				for slot := 1; slot <= 2; slot++ {
					stopped := slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasSuffix(c, fmt.Sprintf(" stop host-demo-%d.service", slot)) })
					if stopped == (slot == current) {
						t.Fatalf("slot %d stopped=%v with accepted slot %d", slot, stopped, current)
					}
				}
			})
		}
	}
}

func TestPendingRecoveryDoesNotRequireGitHub(t *testing.T) {
	f := setup(t, "overlap")
	one := f.approve("r-one", 1, "")
	two := f.approve("r-two", 2, "r-one")
	s := State{Current: &Accepted{one, 1}, Pending: &Accepted{two, 2}, HighWater: 2}
	if err := f.m.save("demo", &s, "interrupted promotion"); err != nil {
		t.Fatal(err)
	}
	f.live = 2
	drained := false
	f.m.drain = func(context.Context, time.Duration) error { drained = true; return nil }
	if err := f.m.RecoverPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	s = f.state()
	if !drained || !s.Hold || s.Pending != nil || s.Current.Release.ID != "r-one" || f.live != 1 {
		t.Fatal("local recovery did not restore/hold accepted route", s)
	}
	f.calls = nil
	if err := f.m.RecoverPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatal("nonpending app unnecessarily restarted")
	}
}

func TestPolicyChangePreservesRecoveryAndRollback(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	f.approve("r-two", 2, "r-one")
	for _, id := range []string{"r-one", "r-two"} {
		if err := f.op("deploy", id); err != nil {
			t.Fatal(err)
		}
	}
	f.approve("r-stale", 3, "r-two")
	f.c.GitHub.WorkflowSHA256 = strings.Repeat("d", 64)
	b, err := json.MarshalIndent(f.c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.m.configDir, "demo.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.op("deploy", "r-stale"); err == nil {
		t.Fatal("new release admitted under superseded policy")
	}
	f.live = 0 // Reboot without a restored Caddy route.
	if err := f.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := f.state(); s.Current.Release.ID != "r-two" || !s.Hold || f.live != 2 {
		t.Fatal("accepted route was not recovered under the new policy", s)
	}
	if err := f.op("rollback", ""); err != nil {
		t.Fatal(err)
	}
	if s := f.state(); s.Current.Release.ID != "r-one" || !s.Hold || s.HighWater != 2 || f.live != 1 {
		t.Fatal("rollback did not preserve the old release, hold, and replay barrier", s)
	}
}

func TestUpdateReleasePolicyPreservesLegacyReceipt(t *testing.T) {
	f := setup(t, "singleton")
	r := f.approve("r-one", 1, "")
	legacy := State{Current: &Accepted{r, 1}, HighWater: 1}
	if err := f.m.save("demo", &legacy, "release accepted by older binary"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reviewed.json")
	next := f.c
	next.GitHub.WorkflowSHA256 = strings.Repeat("d", 64)
	next.ContainerPort++
	if err := atomicJSON(path, next); err != nil {
		t.Fatal(err)
	}
	if err := f.m.UpdateReleasePolicy(path); err == nil {
		t.Fatal("policy update installed an incompatible runtime")
	}
	if c, err := f.m.config("demo"); err != nil || c.hash != f.hash {
		t.Fatal("failed policy update modified the installed manifest", err)
	}
	next.ContainerPort = f.c.ContainerPort
	if err := atomicJSON(path, next); err != nil {
		t.Fatal(err)
	}
	if err := f.m.UpdateReleasePolicy(path); err != nil {
		t.Fatal(err)
	}
	if c, err := f.m.config("demo"); err != nil || c.hash == f.hash || c.GitHub != next.GitHub {
		t.Fatal("reviewed policy was not installed", err)
	}
	if len(f.calls) != 0 || f.state().Current.Release != r {
		t.Fatal("policy update restarted the app or rewrote the receipt")
	}
	if err := f.m.Reconcile(context.Background()); err != nil || f.live != 1 {
		t.Fatal("policy update did not preserve the legacy accepted release", err)
	}
	archive := f.m.retainedManifest("demo", f.hash)
	if err := atomicJSON(archive, next); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := f.m.Reconcile(context.Background()); err == nil || len(f.calls) != 0 {
		t.Fatal("recovery used an archive with the wrong hash", err)
	}
}

func TestReconcileReportsBrokenAppAndRecoversNext(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.m.configDir, "bad.json"), []byte("bad manifest"), 0600); err != nil {
		t.Fatal(err)
	}
	f.live = 0
	err := f.m.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bad:") || f.live != 1 {
		t.Fatal("a broken app must be reported without stranding the next app", err, f.live)
	}
}

func TestFailedOldSlotStopRemainsRecoverable(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	f.approve("r-two", 2, "r-one")
	native := f.m.exec
	f.m.exec = func(ctx context.Context, step string, args ...string) ([]byte, error) {
		if slices.Contains(args, "stop") && slices.Contains(args, "host-demo-1.service") {
			return nil, errors.New("stop failed")
		}
		return native(ctx, step, args...)
	}
	if err := f.op("deploy", "r-two"); err == nil {
		t.Fatal("old-slot stop failure was lost")
	}
	if s := f.state(); s.Current.Release.ID != "r-one" || s.Pending == nil || f.live != 2 {
		t.Fatal("old-slot stop failure discarded the pending recovery receipt", s)
	}
	f.m.exec = native
	if err := f.m.RecoverPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := f.state(); s.Current.Release.ID != "r-one" || s.Pending != nil || !s.Hold || f.live != 1 {
		t.Fatal("pending recovery did not restore the accepted route", s)
	}
}

func TestRuntimeUsesEnrolledHomeAndPrelabelledSecrets(t *testing.T) {
	f := setup(t, "overlap")
	f.c.Mounts = []Mount{{Source: "/etc/minimal-host/app-secrets/demo/key", Target: "/run/secrets/key", ReadOnly: true}, {Source: "/var/lib/minimal-host/apps/demo/data", Target: "/data"}}
	b, _ := json.Marshal(f.c)
	if err := os.WriteFile(filepath.Join(f.m.configDir, "demo.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	_, f.hash, _ = ReadConfig(b)
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.calls {
		if !strings.Contains(call, "HOME=/var/home/app-demo ") {
			t.Fatal("runtime does not use enrolled home", call)
		}
	}
	b, err := os.ReadFile(filepath.Join(f.m.quadletDir, "2001", "host-demo-1.container"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Volume=/etc/minimal-host/app-secrets/demo/key:/run/secrets/key:ro\n") || !strings.Contains(string(b), "Volume=/var/lib/minimal-host/apps/demo/data:/data:rw,z\n") {
		t.Fatal("unsafe secret relabel or data overlap label", string(b))
	}
	if !strings.Contains(string(b), "--memory=134217728 --memory-swap=134217728 --cpus=1.00 --pids-limit=256") {
		t.Fatal("missing actual container resource bounds")
	}
}
func TestHealthRequiresLiveAuthorizedRouteAndReadiness(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	health := func() Health {
		v, err := f.m.Handle(context.Background(), protocol.Request{Op: "health", App: "demo"})
		if err != nil {
			t.Fatal(err)
		}
		return v.(Health)
	}
	if !health().Healthy {
		t.Fatal("accepted healthy app reported unavailable")
	}
	f.live = 2
	if health().Healthy {
		t.Fatal("foreign slot appeared healthy from accepted receipt")
	}
	f.live = 1
	f.m.ready = func(context.Context, Config, int) error { return errors.New("down") }
	if health().Healthy {
		t.Fatal("dead application appeared healthy from accepted receipt")
	}
}

func TestNativeRunnerUsesAccessibleWorkingDirectoryAndRedactsFailures(t *testing.T) {
	output, err := run(context.Background(), "pwd", "/bin/pwd")
	if err != nil || strings.TrimSpace(string(output)) != "/" {
		t.Fatal("native subprocess inherited an inaccessible caller directory", err)
	}
	output, err = run(context.Background(), "sh", "/bin/sh", "-c", "printf 'private-marker'; printf 'private-marker' >&2; exit 7")
	if err == nil || output != nil || err.Error() != "native sh failed (exit 7)" {
		t.Fatal("native failure did not expose only safe operation/exit status", err)
	}
	output, err = run(context.Background(), "sh", "/bin/sh", "-c", "printf 'WARN cgroup' >&2; printf '[]'")
	if err != nil || string(output) != "[]" {
		t.Fatalf("native output mixed with diagnostics: %q %v", output, err)
	}
}

func TestNativeStepOmitsArguments(t *testing.T) {
	for args, want := range map[string]string{
		"/usr/bin/podman image inspect --format {{json .RepoDigests}} ghcr.io/private/app@sha256:abc": "podman image inspect",
		"/usr/bin/podman pull --policy=always ghcr.io/private/app@sha256:abc":                         "podman pull",
		"/usr/bin/systemctl --user stop host-demo-1.service":                                          "systemctl stop",
		"/usr/bin/systemctl --user daemon-reload":                                                     "systemctl daemon-reload",
	} {
		if got := step(strings.Fields(args)); got != want {
			t.Fatalf("step(%s) = %q, want %q", args, got, want)
		}
	}
}

func TestQuadletPublicationIgnoresRestrictiveUmask(t *testing.T) {
	f := setup(t, "overlap")
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	f.approve("r-one", 1, "")
	if err := f.op("deploy", "r-one"); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(f.m.quadletDir, "2001")
	file := filepath.Join(directory, "host-demo-1.container")
	st, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0644 {
		t.Fatalf("Quadlet mode %04o is unreadable to the user generator", st.Mode().Perm())
	}
	st, err = os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0755 {
		t.Fatalf("Quadlet directory mode %04o is not traversable", st.Mode().Perm())
	}
	old, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	err = atomicFile(file, 0644, func(w io.Writer) error {
		if _, err := io.WriteString(w, "partial candidate"); err != nil {
			return err
		}
		visible, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(visible, old) {
			t.Fatal("incomplete Quadlet became visible before publication")
		}
		paths, err := filepath.Glob(filepath.Join(directory, "*.container"))
		if err != nil {
			t.Fatal(err)
		}
		if len(paths) != 1 || paths[0] != file {
			t.Fatal("temporary file is visible as a Quadlet", paths)
		}
		return errors.New("simulated write failure")
	})
	if err == nil {
		t.Fatal("write failure was hidden")
	}
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, old) {
		t.Fatal("failed publication damaged the prior Quadlet")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("failed publication leaked temporary source", entries)
	}
}

func TestReconcileWaitsForPrimaryProxyReadiness(t *testing.T) {
	f := setup(t, "overlap")
	calls := 0
	f.m.routeSlot = func(context.Context, Config) (int, error) {
		calls++
		if calls <= 2 {
			return 0, errProxyUnavailable
		}
		return f.live, nil
	}
	if err := f.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls < 4 {
		t.Fatal("proxy was not retried and then read back", calls)
	}
	s := f.state()
	if s.Hold || s.Current != nil || s.Pending != nil {
		t.Fatal("ordinary bounded startup changed accepted state", s)
	}
}
func TestProxyReadinessTimeoutHoldsWithoutAccepting(t *testing.T) {
	f := setup(t, "overlap")
	calls := 0
	f.m.routeSlot = func(context.Context, Config) (int, error) { calls++; return 0, errProxyUnavailable }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := f.m.Reconcile(ctx)
	if !errors.Is(err, errProxyUnavailable) || time.Since(started) > time.Second {
		t.Fatal("proxy startup timeout was not bounded or visible", err)
	}
	s := f.state()
	if calls == 0 || !s.Hold || s.Current != nil || s.Pending != nil || len(f.calls) != 0 {
		t.Fatal("unavailable proxy admitted runtime effects", s)
	}
}
func TestProxyReadinessNeverRetriesForeignRoute(t *testing.T) {
	f := setup(t, "overlap")
	calls := 0
	f.m.routeSlot = func(context.Context, Config) (int, error) {
		calls++
		return 0, errors.New("proxy route is outside installed application policy")
	}
	err := f.m.Reconcile(context.Background())
	if err == nil || calls != 1 {
		t.Fatal("foreign route was treated as startup unavailability", err, calls)
	}
	s := f.state()
	if !s.Hold || s.Current != nil || len(f.calls) != 0 {
		t.Fatal("invalid route changed runtime state", s)
	}
}

func TestApplicationIdentityMatchesFirewallEnrollment(t *testing.T) {
	f := setup(t, "overlap")
	for _, change := range []func(*Config){func(c *Config) { c.User = "root" }, func(c *Config) { c.User = "app-other" }, func(c *Config) { c.UID = 1000 }, func(c *Config) { c.UID = 3000 }} {
		c := f.c
		change(&c)
		if c.validate() == nil {
			t.Fatal("identity outside installed firewall enrollment was accepted", c.User, c.UID)
		}
	}
	for _, lookup := range []func(string) (string, error){func(string) (string, error) { return "0", nil }, func(string) (string, error) { return "2002", nil }, func(string) (string, error) { return "", errors.New("not enrolled") }} {
		f.m.lookupUser = lookup
		f.approve("r-one", 1, "")
		if err := f.op("deploy", "r-one"); err == nil {
			t.Fatal("mismatched runtime identity admitted")
		}
		if len(f.calls) != 0 {
			t.Fatal("identity mismatch reached native commands")
		}
	}
}

func TestHandleServesEveryProtocolOp(t *testing.T) {
	f := setup(t, "overlap")
	f.approve("r-one", 1, "")
	for _, op := range protocol.Ops {
		q := protocol.Request{Op: op.Name, App: "demo"}
		if op.TakesRelease {
			q.Release = "r-one"
		}
		if _, err := f.m.Handle(context.Background(), q); errors.Is(err, protocol.ErrNotPermitted) {
			t.Fatal("protocol operation has no engine handler", op.Name)
		}
	}
}
