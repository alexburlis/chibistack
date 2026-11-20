package engine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"minimal.host/platform/internal/protocol"
)

type manifest struct {
	Config
	hash string
	data []byte
}

func (m *Manager) readManifest(path string) (manifest, error) {
	if err := m.trust(path); err != nil {
		return manifest{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return manifest{}, err
	}
	defer f.Close()
	const manifestLimit = 64 << 10
	b, err := io.ReadAll(io.LimitReader(f, manifestLimit+1))
	if err != nil || len(b) > manifestLimit {
		return manifest{}, errors.New("manifest unavailable")
	}
	c, hash, err := ReadConfig(b)
	return manifest{Config: c, hash: hash, data: b}, err
}

func (m *Manager) config(app string) (manifest, error) {
	if !protocol.ValidName(app) {
		return manifest{}, errors.New("unknown application")
	}
	c, err := m.readManifest(filepath.Join(m.configDir, app+".json"))
	if err != nil {
		return manifest{}, err
	}
	if c.App != app {
		return manifest{}, errors.New("configuration application mismatch")
	}
	uid, err := m.lookupUser(c.User)
	if err != nil || uid != strconv.Itoa(c.UID) {
		return manifest{}, errors.New("enrolled application identity does not match installed manifest")
	}
	return c, nil
}

func sameRuntime(a, b Config) bool {
	a.GitHub, b.GitHub = GitHub{}, GitHub{}
	if len(a.Mounts) == 0 && len(b.Mounts) == 0 {
		a.Mounts, b.Mounts = nil, nil
	}
	return reflect.DeepEqual(a, b)
}

func (m *Manager) retainedManifest(app, hash string) string {
	return filepath.Join(m.stateDir, app+"-"+hash+".manifest")
}

// Save the exact approved bytes before writing a receipt or replacing the policy.
func (m *Manager) retainManifest(c manifest) error {
	path := m.retainedManifest(c.App, c.hash)
	old, err := m.readManifest(path)
	if err == nil && bytes.Equal(old.data, c.data) {
		return nil
	}
	if !os.IsNotExist(err) {
		return errors.New("retained manifest is untrusted or does not match its hash")
	}
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return err
	}
	if err := m.trust(m.stateDir); err != nil {
		return err
	}
	return writeManifest(path, c.data, 0600)
}

func writeManifest(path string, data []byte, mode os.FileMode) error {
	return atomicFile(path, mode, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// Only releases already named by durable receipts can use a retained manifest.
func (m *Manager) recoverable(c manifest, r Release) error {
	if r.ConfigSHA256 == c.hash {
		return r.validate(c.Config, c.hash)
	}
	if !hex64.MatchString(r.ConfigSHA256) {
		return errors.New("invalid release manifest hash")
	}
	old, err := m.readManifest(m.retainedManifest(c.App, r.ConfigSHA256))
	if err != nil || old.hash != r.ConfigSHA256 {
		return errors.New("original release manifest unavailable or invalid")
	}
	if !sameRuntime(c.Config, old.Config) {
		return errors.New("release runtime differs from installed manifest")
	}
	return r.validate(old.Config, old.hash)
}

// UpdateReleasePolicy replaces only the GitHub policy and JSON formatting.
func (m *Manager) UpdateReleasePolicy(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	next, err := m.readManifest(path)
	if err != nil {
		return err
	}
	held, err := m.lock()
	if err != nil {
		return err
	}
	defer held.release()
	c, err := m.config(next.App)
	if err != nil {
		return err
	}
	if !sameRuntime(c.Config, next.Config) {
		return errors.New("release policy update cannot change the application runtime")
	}
	s, err := m.admissible(c.App)
	if err != nil {
		return err
	}
	for _, accepted := range []*Accepted{s.Current, s.Previous} {
		if accepted != nil {
			if err := m.recoverable(c, accepted.Release); err != nil {
				return err
			}
		}
	}
	if err := m.retainManifest(c); err != nil {
		return err
	}
	if next.hash == c.hash {
		return nil
	}
	return writeManifest(filepath.Join(m.configDir, c.App+".json"), next.data, 0644)
}
