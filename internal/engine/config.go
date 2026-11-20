package engine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"minimal.host/platform/internal/protocol"
)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var imageSegment = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
var hostPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]+[a-z0-9]$`)
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
var cpuPattern = regexp.MustCompile(`^[1-9][0-9]{0,2}%$`)

// Host layout that render-host creates and the engine reads.
const (
	ConfigDir   = "/etc/minimal-host/apps"
	StateDir    = "/var/lib/minimal-host/state"
	ApprovalDir = "/var/lib/minimal-host/approved"
	QuadletRoot = "/etc/containers/systemd/users"
	LockPath    = "/run/minimal-host/lifecycle.lock"

	// The firewall confines this UID range.
	MinAppUID = 2000
	MaxAppUID = 2999
)

const (
	modeOverlap   = "overlap"
	modeSingleton = "singleton"

	maxReadySeconds = 300
	maxDrainSeconds = 3600

	// The host firewall lets the proxy reach only this loopback range.
	minBackendPort = 18000
	maxBackendPort = 18999
)

// The margin covers native image and unit work. The helper unit stops a
// request after 75 minutes (RuntimeMaxSec), so this must stay below that.
const OperationTimeout = (maxReadySeconds+maxDrainSeconds)*time.Second + 5*time.Minute

// Config is installed by the administrator, never supplied by a release request.
type Config struct {
	App           string  `json:"app"`
	User          string  `json:"user"`
	UID           int     `json:"uid"`
	ImageRepo     string  `json:"image_repo"`
	Hostname      string  `json:"hostname"`
	Ports         [2]int  `json:"ports"`
	ContainerPort int     `json:"container_port"`
	ContainerUID  int     `json:"container_uid"`
	ReadinessPath string  `json:"readiness_path"`
	Mode          string  `json:"mode"`
	MemoryBytes   int64   `json:"memory_bytes"`
	CPUQuota      string  `json:"cpu_quota"`
	ReadySeconds  int     `json:"ready_seconds"`
	DrainSeconds  int     `json:"drain_seconds"`
	Mounts        []Mount `json:"mounts,omitempty"`
	GitHub        GitHub  `json:"github"`
}
type Mount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}
type GitHub struct {
	SigningPublicKey string `json:"signing_public_key"`
	Repo             string `json:"repo"`
	Branch           string `json:"branch"`
	Environment      string `json:"environment"`
	CreatorID        int64  `json:"creator_id"`
	WorkflowPath     string `json:"workflow_path"`
	WorkflowSHA256   string `json:"workflow_sha256"`
}
type Release struct {
	ID              string `json:"id"`
	App             string `json:"app"`
	SHA             string `json:"sha"`
	Digest          string `json:"digest"`
	ConfigSHA256    string `json:"config_sha256"`
	RunID           int64  `json:"run_id"`
	ExpectedCurrent string `json:"expected_current"`
}

func ReadConfig(data []byte) (Config, string, error) {
	var c Config
	if err := protocol.DecodeStrict(data, &c); err != nil {
		return c, "", err
	}
	if err := c.validate(); err != nil {
		return c, "", err
	}
	sum := sha256.Sum256(data)
	return c, hex.EncodeToString(sum[:]), nil
}

func (c Config) Home() string      { return "/var/home/" + c.User }
func (c Config) Network() string   { return "host-" + c.App + "-private" }
func (c Config) DataDir() string   { return "/var/lib/minimal-host/apps/" + c.App }
func (c Config) SecretDir() string { return "/etc/minimal-host/app-secrets/" + c.App }
func (c Config) secret(m Mount) bool {
	return strings.HasPrefix(m.Source, c.SecretDir()+"/")
}
func (c Config) backend(slot int) string { return fmt.Sprintf("127.0.0.1:%d", c.Ports[slot-1]) }

func (c Config) validate() error {
	if !protocol.ValidName(c.App) || !protocol.ValidName(c.User) || c.User != "app-"+c.App || c.UID < MinAppUID || c.UID > MaxAppUID {
		return errors.New("invalid application identity")
	}
	if !validImageRepo(c.ImageRepo) || !hostPattern.MatchString(c.Hostname) || strings.Contains(c.Hostname, "..") {
		return errors.New("invalid image repository or hostname")
	}
	if c.Ports[0] < minBackendPort || c.Ports[0] > maxBackendPort || c.Ports[1] < minBackendPort || c.Ports[1] > maxBackendPort || c.Ports[0] == c.Ports[1] || c.ContainerPort < 1 || c.ContainerPort > 65535 || c.ContainerUID < 1 {
		return errors.New("invalid ports or container UID")
	}
	if c.Mode != modeOverlap && c.Mode != modeSingleton {
		return errors.New("mode must be overlap or singleton")
	}
	if c.MemoryBytes < 16<<20 || !cpuPattern.MatchString(c.CPUQuota) || c.ReadySeconds < 1 || c.ReadySeconds > maxReadySeconds || c.DrainSeconds < 1 || c.DrainSeconds > maxDrainSeconds {
		return errors.New("invalid resource or time bound")
	}
	if !strings.HasPrefix(c.ReadinessPath, "/") || strings.ContainsAny(c.ReadinessPath, "\r\n?# ") {
		return errors.New("invalid readiness path")
	}
	for _, m := range c.Mounts {
		allowed := strings.HasPrefix(m.Source, c.DataDir()+"/") || (m.ReadOnly && c.secret(m))
		if !allowed || filepath.Clean(m.Source) != m.Source || !filepath.IsAbs(m.Target) || filepath.Clean(m.Target) != m.Target || m.Target == "/" || strings.ContainsAny(m.Source+m.Target, "\r\n\t :%\\") {
			return errors.New("invalid application mount")
		}
	}
	if !repoPattern.MatchString(c.GitHub.Repo) || c.GitHub.CreatorID < 1 || c.GitHub.Branch == "" || c.GitHub.Environment == "" || !strings.HasPrefix(c.GitHub.WorkflowPath, ".github/workflows/") || !hex64.MatchString(c.GitHub.WorkflowSHA256) {
		return errors.New("invalid GitHub release policy")
	}
	_, err := c.GitHub.publicKey()
	return err
}

func (g GitHub) publicKey() (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(g.SigningPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || bytes.Equal(pub, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New("invalid Ed25519 release verification key")
	}
	return pub, nil
}

func (r Release) validate(c Config, configHash string) error {
	if !protocol.ValidName(r.ID) || r.App != c.App || !hex40.MatchString(r.SHA) || !strings.HasPrefix(r.Digest, "sha256:") || !hex64.MatchString(strings.TrimPrefix(r.Digest, "sha256:")) || r.ConfigSHA256 != configHash || r.RunID < 1 {
		return errors.New("release does not match installed policy")
	}
	if r.ExpectedCurrent != "" && !protocol.ValidName(r.ExpectedCurrent) {
		return errors.New("invalid expected current release")
	}
	return nil
}

func trusted(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("untrusted installed path: %s", p)
		}
		if p == "/" {
			return nil
		}
	}
}

func validImageRepo(ref string) bool {
	if len(ref) > 255 || strings.ContainsAny(ref, "?#@\\\r\n\t ") {
		return false
	}
	u, err := url.Parse("https://" + ref)
	if err != nil || u.User != nil || u.Host == "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil && (!hostPattern.MatchString(host) && host != "localhost") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if !strings.HasPrefix(u.Path, "/") {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if !imageSegment.MatchString(part) {
			return false
		}
	}
	return true
}
