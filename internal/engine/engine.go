package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"minimal.host/platform/internal/protocol"
)

type Accepted struct {
	Release Release `json:"release"`
	Slot    int     `json:"slot"`
}
type State struct {
	Current   *Accepted `json:"current,omitempty"`
	Previous  *Accepted `json:"previous,omitempty"`
	Pending   *Accepted `json:"pending,omitempty"`
	Hold      bool      `json:"hold"`
	Updated   string    `json:"updated"`
	Event     string    `json:"event"`
	HighWater int64     `json:"high_water"`
}
type Health struct {
	Healthy bool `json:"healthy"`
	Pending bool `json:"pending"`
}
type Logs struct {
	Event   string `json:"event"`
	Updated string `json:"updated"`
}

func (s State) current() string {
	if s.Current == nil {
		return ""
	}
	return s.Current.Release.ID
}

// Manager drives each app's two slots. The function fields are the native
// world: tests replace them.
type Manager struct {
	configDir, stateDir, approvalDir, quadletDir, lockPath, caddySocket string

	exec        runner
	trust       func(string) error
	lookupUser  func(string) (string, error)
	ready       func(context.Context, Config, int) error
	switchRoute func(context.Context, Config, int) error
	routeSlot   func(context.Context, Config) (int, error)
	drain       func(context.Context, time.Duration) error
}

func New() *Manager {
	m := &Manager{configDir: ConfigDir, stateDir: StateDir, approvalDir: ApprovalDir, quadletDir: QuadletRoot, lockPath: LockPath, caddySocket: "/run/minimal-host/proxy/admin.sock", exec: run, trust: trusted, lookupUser: enrolledUID, drain: delay}
	m.ready = m.waitReady
	m.switchRoute = m.route
	m.routeSlot = m.liveRoute
	return m
}

func enrolledUID(name string) (string, error) {
	identity, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return identity.Uid, nil
}

var errNotConfigured = errors.New("application is not configured")

func (m *Manager) apps() ([]string, error) {
	entries, err := os.ReadDir(m.configDir)
	if err != nil {
		return nil, err
	}
	var apps []string
	for _, entry := range entries {
		if app, ok := strings.CutSuffix(entry.Name(), ".json"); ok {
			apps = append(apps, app)
		}
	}
	return apps, nil
}

func (m *Manager) approvalPath(app, id string) string {
	return filepath.Join(m.approvalDir, app, id+".json")
}

func (m *Manager) release(c Config, hash, id string) (Release, error) {
	var r Release
	if !protocol.ValidName(id) {
		return r, errors.New("invalid release identifier")
	}
	p := m.approvalPath(c.App, id)
	if err := m.trust(p); err != nil {
		return r, errors.New("release is not approved")
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 4096 {
		return r, errors.New("release is not approved")
	}
	if err = protocol.DecodeStrict(b, &r); err == nil {
		err = r.validate(c, hash)
	}
	if r.ID != id {
		err = errors.New("release identifier mismatch")
	}
	return r, err
}

func (m *Manager) statePath(app string) string { return filepath.Join(m.stateDir, app+".json") }

func (m *Manager) state(app string) (State, error) {
	var s State
	p := m.statePath(app)
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err = m.trust(p); err != nil {
		return s, err
	}
	if len(b) > 16384 {
		return s, errors.New("oversized release state")
	}
	if err = protocol.DecodeStrict(b, &s); err != nil {
		return s, errors.New("invalid release state")
	}
	for _, a := range []*Accepted{s.Current, s.Previous, s.Pending} {
		if a != nil && (a.Slot < 1 || a.Slot > 2 || a.Release.App != app || !protocol.ValidName(a.Release.ID)) {
			return s, errors.New("invalid accepted release")
		}
	}
	return s, nil
}

func (m *Manager) save(app string, s *State, event string) error {
	s.Updated = time.Now().UTC().Format(time.RFC3339)
	s.Event = event
	return atomicJSON(m.statePath(app), s)
}

func atomicJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicFile(path, 0600, func(w io.Writer) error { _, err := w.Write(b); return err })
}

func atomicFile(path string, mode os.FileMode, write func(io.Writer) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		err = write(f)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lifecycle is held while one process mutates the host. Backups and OS updates
// take the same lock file.
type lifecycle struct{ file *os.File }

func (m *Manager) lock() (*lifecycle, error) {
	f, err := os.OpenFile(m.lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("busy; no mutation started")
	}
	return &lifecycle{f}, nil
}

func (l *lifecycle) release() {
	syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	l.file.Close()
}

func (m *Manager) Handle(ctx context.Context, q protocol.Request) (any, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	if q.Op == protocol.Deploy || q.Op == protocol.Rollback {
		return m.locked(func(held *lifecycle) (State, error) {
			c, err := m.config(q.App)
			if err != nil {
				return State{}, errNotConfigured
			}
			if q.Op == protocol.Deploy {
				return m.deploy(ctx, held, c, q.Release)
			}
			return m.rollback(ctx, held, c)
		})
	}
	c, err := m.config(q.App)
	if err != nil {
		return nil, errNotConfigured
	}
	switch q.Op {
	case protocol.Status, protocol.DeploymentStatus:
		return m.state(c.App)
	case protocol.Logs:
		s, err := m.state(c.App)
		return Logs{Event: s.Event, Updated: s.Updated}, err
	case protocol.Health:
		return m.health(ctx, c.Config)
	}
	return nil, protocol.ErrNotPermitted
}

func (m *Manager) locked(mutation func(*lifecycle) (State, error)) (State, error) {
	held, err := m.lock()
	if err != nil {
		return State{}, err
	}
	defer held.release()
	return mutation(held)
}

func (m *Manager) Health(ctx context.Context, app string) (Health, error) {
	c, err := m.config(app)
	if err != nil {
		return Health{}, err
	}
	return m.health(ctx, c.Config)
}

func (m *Manager) health(ctx context.Context, c Config) (Health, error) {
	s, err := m.state(c.App)
	if err != nil {
		return Health{}, err
	}
	result := Health{Pending: s.Pending != nil}
	slot, err := m.routeSlot(ctx, c)
	if err != nil {
		return result, err
	}
	authorized := s.Current != nil && slot == s.Current.Slot || s.Pending != nil && slot == s.Pending.Slot
	if slot == 0 || !authorized {
		return result, nil
	}
	result.Healthy = m.ready(ctx, c, slot) == nil
	return result, nil
}

func (m *Manager) admissible(app string) (State, error) {
	s, err := m.state(app)
	if err == nil && s.Pending != nil {
		err = errors.New("interrupted release; reconcile required")
	}
	return s, err
}

func (m *Manager) deploy(ctx context.Context, held *lifecycle, c manifest, id string) (State, error) {
	s, err := m.admissible(c.App)
	if err != nil {
		return s, err
	}
	if s.Hold {
		return s, errors.New("application admission held")
	}
	target, err := m.release(c.Config, c.hash, id)
	if err != nil {
		return s, err
	}
	if s.current() == target.ID {
		return s, nil
	}
	if target.RunID <= s.HighWater {
		return s, errors.New("superseded release request")
	}
	if target.ExpectedCurrent != s.current() {
		return s, errors.New("stale release request")
	}
	if err := m.retainManifest(c); err != nil {
		return s, err
	}
	return m.promote(ctx, held, c, s, target)
}

// rollback holds admission even when it fails.
func (m *Manager) rollback(ctx context.Context, held *lifecycle, c manifest) (State, error) {
	s, err := m.admissible(c.App)
	if err != nil {
		return s, err
	}
	s.Hold = true
	if err = m.save(c.App, &s, "rollback admission held"); err != nil {
		return s, err
	}
	if s.Previous == nil {
		return s, errors.New("no compatible previous release retained")
	}
	previous := s.Previous.Release
	if err := m.recoverable(c, previous); err != nil {
		return s, err
	}
	target, err := m.release(c.Config, previous.ConfigSHA256, previous.ID)
	if err != nil {
		return s, err
	}
	if target != previous {
		return s, errors.New("rollback approval does not match the previous receipt")
	}
	if s.current() == target.ID {
		return s, nil
	}
	return m.promote(ctx, held, c, s, target)
}

// promote starts target in the idle slot, routes to it once ready and records
// acceptance. Any failure leaves a receipt that admission or reconcile acts on.
func (m *Manager) promote(ctx context.Context, _ *lifecycle, installed manifest, s State, target Release) (State, error) {
	c := installed.Config
	if s.Current != nil {
		if err := m.recoverable(installed, s.Current.Release); err != nil {
			return s, err
		}
	}
	slot := 1
	if s.Current != nil {
		slot = 3 - s.Current.Slot
	}
	candidate := Accepted{Release: target, Slot: slot}
	s.Pending = &candidate
	if target.RunID > s.HighWater {
		s.HighWater = target.RunID
	}
	if err := m.save(c.App, &s, "candidate pending"); err != nil {
		return s, err
	}
	if err := m.stop(ctx, c, slot); err != nil {
		return s, err
	}
	oldStopped := false
	if c.Mode == modeSingleton && s.Current != nil {
		if err := m.stop(ctx, c, s.Current.Slot); err != nil {
			return s, err
		}
		oldStopped = true
	}
	err := m.start(ctx, c, candidate)
	if err == nil {
		err = m.ready(ctx, c, slot)
	}
	if err != nil {
		if ctx.Err() != nil {
			return s, errors.New("interrupted candidate; reconcile required")
		}
		if stopErr := m.stop(ctx, c, slot); stopErr != nil {
			return s, errors.New("candidate cleanup failed; reconcile required")
		}
		if oldStopped {
			if restoreErr := m.start(ctx, c, *s.Current); restoreErr != nil {
				return s, errors.New("singleton restore failed; reconcile required")
			}
		}
		s.Pending = nil
		s.Hold = true
		if saveErr := m.save(c.App, &s, "candidate failed; admission held"); saveErr != nil {
			return s, saveErr
		}
		return s, err
	}
	if err = m.switchRoute(ctx, c, slot); err != nil {
		s.Hold = true
		return s, errors.Join(err, m.save(c.App, &s, "proxy outcome uncertain; reconcile required"))
	}
	if actual, readErr := m.routeSlot(ctx, c); readErr != nil || actual != slot {
		return s, errors.New("proxy readback mismatch; reconcile required")
	}
	if s.Current != nil && c.Mode == modeOverlap {
		if err = m.drain(ctx, time.Duration(c.DrainSeconds)*time.Second); err != nil {
			return s, errors.New("promotion interrupted; reconcile required")
		}
		if err = m.stop(ctx, c, s.Current.Slot); err != nil {
			return s, errors.New("old slot stop failed; reconcile required")
		}
	}
	s.Previous = s.Current
	s.Current = &candidate
	s.Pending = nil
	if err = m.save(c.App, &s, "release accepted"); err != nil {
		return s, err
	}
	return s, nil
}

func (m *Manager) Reconcile(ctx context.Context) error      { return m.reconcile(ctx, false) }
func (m *Manager) RecoverPending(ctx context.Context) error { return m.reconcile(ctx, true) }

func (m *Manager) reconcile(ctx context.Context, pendingOnly bool) error {
	held, err := m.lock()
	if err != nil {
		return err
	}
	defer held.release()
	apps, err := m.apps()
	if err != nil {
		return err
	}
	var failures []error
	for _, app := range apps {
		if err := m.recoverApp(ctx, app, pendingOnly); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", app, err))
		}
	}
	return errors.Join(failures...)
}

func (m *Manager) recoverApp(ctx context.Context, app string, pendingOnly bool) error {
	s, err := m.state(app)
	if err != nil || (pendingOnly && s.Pending == nil) {
		return err
	}
	installed, err := m.config(app)
	if err != nil {
		return err
	}
	c := installed.Config
	if s.Current != nil {
		if err := m.recoverable(installed, s.Current.Release); err != nil {
			return err
		}
	}
	expectedSlot := 0
	if s.Current != nil {
		expectedSlot = s.Current.Slot
	}
	actualSlot, routeErr := m.waitProxy(ctx, c)
	if routeErr != nil {
		s.Hold = true
		if saveErr := m.save(app, &s, "proxy recovery failed; admission held"); saveErr != nil {
			return saveErr
		}
		return routeErr
	}
	if s.Pending != nil || actualSlot != expectedSlot {
		s.Hold = true
		if err = m.save(app, &s, "recovery admission held"); err != nil {
			return err
		}
	}
	if c.Mode == modeSingleton {
		if err = m.stopExcept(ctx, c, expectedSlot); err != nil {
			return err
		}
	}
	slot := 0
	if s.Current != nil {
		if err = m.start(ctx, c, *s.Current); err != nil {
			return err
		}
		if err = m.ready(ctx, c, s.Current.Slot); err != nil {
			return err
		}
		slot = s.Current.Slot
	}
	if err = m.switchRoute(ctx, c, slot); err != nil {
		return err
	}
	if actual, readErr := m.routeSlot(ctx, c); readErr != nil || actual != slot {
		return errors.New("reconciled route readback mismatch")
	}
	if c.Mode == modeOverlap && actualSlot != 0 && actualSlot != slot {
		if err = m.drain(ctx, time.Duration(c.DrainSeconds)*time.Second); err != nil {
			return err
		}
	}
	if err = m.stopExcept(ctx, c, slot); err != nil {
		return err
	}
	s.Pending = nil
	return m.save(app, &s, "accepted route reconciled")
}

func (m *Manager) Resume(app string, afterRunID int64) error {
	held, err := m.lock()
	if err != nil {
		return err
	}
	defer held.release()
	if _, err = m.config(app); err != nil {
		return err
	}
	s, err := m.state(app)
	if err != nil {
		return err
	}
	if s.Pending != nil {
		return errors.New("reconcile before resuming")
	}
	if afterRunID < s.HighWater {
		return errors.New("resume requires a workflow-run barrier at least the recorded high-water mark")
	}
	s.HighWater = afterRunID
	s.Hold = false
	return m.save(app, &s, "administrator resumed admission")
}
