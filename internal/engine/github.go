package engine

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"minimal.host/platform/internal/protocol"
)

type GitHubClient struct {
	baseURL, token string
	client         *http.Client
}
type deployment struct {
	Task        string `json:"task"`
	ID          int64  `json:"id"`
	SHA         string `json:"sha"`
	Environment string `json:"environment"`
	Creator     struct {
		ID int64 `json:"id"`
	} `json:"creator"`
	Payload json.RawMessage `json:"payload"`
}

func NewGitHub(token string) *GitHubClient {
	return &GitHubClient{baseURL: "https://api.github.com", token: token, client: &http.Client{Transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second}, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("GitHub redirect rejected") }}}
}
func (g *GitHubClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", g.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	r, err := g.client.Do(req)
	if err != nil {
		return errors.New("GitHub request failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return errors.New("GitHub rejected read request")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return errors.New("GitHub response exceeded bound")
	}
	return json.Unmarshal(b, out)
}

type request struct {
	deployment
	signed signedRelease
	err    error
}

func (r request) runID() int64 {
	if r.err != nil {
		return 0
	}
	return r.signed.RunID
}

func (g *GitHubClient) latest(ctx context.Context, c Config, hash string, highWater int64) (*Release, error) {
	repo := "/repos/" + c.GitHub.Repo
	var entries []deployment
	if err := g.get(ctx, repo+"/deployments?environment="+url.QueryEscape(c.GitHub.Environment)+"&per_page=30", &entries); err != nil {
		return nil, err
	}
	requests := make([]request, len(entries))
	for i, d := range entries {
		signed, err := decodeEnvelope(d.Payload)
		requests[i] = request{d, signed, err}
	}
	slices.SortStableFunc(requests, func(a, b request) int { return cmp.Compare(b.runID(), a.runID()) })
	// The newest authorized request is the sole candidate; a malformed authorized request fails visibly.
	for _, d := range requests {
		if d.Task != "minimal-host" || d.Creator.ID != c.GitHub.CreatorID || d.Environment != c.GitHub.Environment {
			continue
		}
		if d.err != nil {
			return nil, d.err
		}
		signed := d.signed
		if signed.Release.App != "" && signed.Release.App != c.App {
			continue
		}
		pub, err := c.GitHub.publicKey()
		if err != nil {
			return nil, err
		}
		if !ed25519.Verify(pub, signed.raw, signed.signature) {
			return nil, errors.New("release signature verification failed")
		}
		if signed.Repository != c.GitHub.Repo || signed.Workflow != c.GitHub.WorkflowPath || signed.RunAttempt != 1 {
			return nil, errors.New("signed source policy mismatch")
		}
		r := signed.Release
		if err := r.validate(c, hash); err != nil {
			return nil, err
		}
		if d.SHA != r.SHA {
			return nil, errors.New("deployment source mismatch")
		}
		if r.RunID <= highWater {
			return nil, nil
		}
		var run struct {
			ID         int64  `json:"id"`
			HeadSHA    string `json:"head_sha"`
			HeadBranch string `json:"head_branch"`
			Event      string `json:"event"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			Path       string `json:"path"`
			RunAttempt int    `json:"run_attempt"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if err := g.get(ctx, repo+"/actions/runs/"+strconv.FormatInt(r.RunID, 10), &run); err != nil {
			return nil, err
		}
		if run.Status != "completed" {
			return nil, nil
		}
		if run.ID != r.RunID || run.Repository.FullName != c.GitHub.Repo || run.HeadSHA != r.SHA || run.HeadBranch != c.GitHub.Branch || run.Event != "push" || run.Conclusion != "success" || run.Path != c.GitHub.WorkflowPath || run.RunAttempt != 1 {
			return nil, errors.New("workflow run does not satisfy installed release policy")
		}
		var ref struct {
			Object struct {
				SHA string `json:"sha"`
			} `json:"object"`
		}
		if err := g.get(ctx, repo+"/git/ref/heads/"+url.PathEscape(c.GitHub.Branch), &ref); err != nil {
			return nil, err
		}
		if ref.Object.SHA != r.SHA {
			return nil, errors.New("deployment is not current approved branch head")
		}
		var content struct {
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		}
		if err := g.get(ctx, repo+"/contents/"+c.GitHub.WorkflowPath+"?ref="+r.SHA, &content); err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
		if err != nil || content.Encoding != "base64" || len(b) > 65536 {
			return nil, errors.New("trusted workflow content unavailable")
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != c.GitHub.WorkflowSHA256 {
			return nil, errors.New("workflow differs from installed trusted configuration")
		}
		return &r, nil
	}
	return nil, nil
}

// Poll checks every app independently, so one app's failure does not stop
// another app's releases.
func (m *Manager) Poll(ctx context.Context, g *GitHubClient) error {
	apps, err := m.apps()
	if err != nil {
		return err
	}
	var failures []error
	for _, app := range apps {
		if err := m.pollApp(ctx, g, app); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", app, err))
		}
	}
	return errors.Join(failures...)
}

func (m *Manager) pollApp(ctx context.Context, g *GitHubClient, app string) error {
	c, err := m.config(app)
	if err != nil {
		return err
	}
	observed, err := m.state(app)
	if err != nil {
		return err
	}
	if observed.Hold || observed.Pending != nil {
		return nil
	}
	candidate, err := g.latest(ctx, c.Config, c.hash, observed.HighWater)
	if err != nil || candidate == nil {
		return err
	}
	held, err := m.lock()
	if err != nil {
		return err
	}
	defer held.release()
	installed, err := m.config(app)
	if err != nil {
		return err
	}
	if installed.hash != c.hash {
		return errors.New("installed manifest changed during release verification")
	}

	s, err := m.state(app)
	if err != nil {
		return err
	}
	if s.Hold || s.Pending != nil || candidate.RunID <= s.HighWater {
		return nil
	}
	if s.Current != nil {
		var comparison struct {
			Status string `json:"status"`
		}
		// Only the first page lists changed files with patches; page 2 keeps the status within the read bound.
		path := "/repos/" + c.GitHub.Repo + "/compare/" + s.Current.Release.SHA + "..." + candidate.SHA + "?per_page=1&page=2"
		if err = g.get(ctx, path, &comparison); err != nil {
			return err
		}
		if comparison.Status != "ahead" && comparison.Status != "identical" {
			return errors.New("non-descendant release rejected")
		}
	}
	if candidate.ExpectedCurrent != "" && candidate.ExpectedCurrent != s.current() {
		return errors.New("stale deployment expectation")
	}
	candidate.ExpectedCurrent = s.current()
	path := m.approvalPath(app, candidate.ID)
	if old, readErr := os.ReadFile(path); readErr == nil {
		var approved Release
		if protocol.DecodeStrict(old, &approved) != nil || approved != *candidate {
			return errors.New("release identifier reuse rejected")
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	} else if err = atomicJSON(path, candidate); err != nil {
		return err
	}
	_, err = m.deploy(ctx, held, installed, candidate.ID)
	return err
}

type signedRelease struct {
	Release
	Repository string `json:"repository"`
	Workflow   string `json:"workflow"`
	RunAttempt int    `json:"run_attempt"`
	raw        []byte
	signature  []byte
}
type signedEnvelope struct {
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

func decodeEnvelope(data []byte) (signedRelease, error) {
	var signed signedRelease
	var env signedEnvelope
	if len(data) > 8192 || protocol.DecodeStrict(data, &env) != nil {
		return signed, errors.New("invalid signed release envelope")
	}
	body, err := base64.StdEncoding.DecodeString(env.Body)
	if err != nil || len(body) > 4096 {
		return signed, errors.New("invalid signed release body")
	}
	signature, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return signed, errors.New("invalid release signature")
	}
	if err = protocol.DecodeStrict(body, &signed); err != nil {
		return signed, errors.New("invalid signed release payload")
	}
	signed.raw = body
	signed.signature = signature
	return signed, nil
}
