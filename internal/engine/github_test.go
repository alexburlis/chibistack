package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGitHubAuthorizationAndPullOnlyAdmission(t *testing.T) {
	for _, kind := range []string{"ok", "wrong-creator", "failed-run", "pending-run", "rerun", "changed-workflow", "policy-changed-during-read", "old-branch", "held", "wrong-digest", "wrong-source", "ahead", "behind", "diverged", "forged-signature", "changed-digest", "unsigned", "signed-wrong-repo", "automatic-environment", "other-app", "earlier-app-fails", "older-listed-first"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t, "overlap")
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			f.c.GitHub.SigningPublicKey = base64.StdEncoding.EncodeToString(pub)
			workflow := []byte("trusted-reviewed-workflow\n")
			sum := sha256.Sum256(workflow)
			f.c.GitHub.WorkflowSHA256 = hex.EncodeToString(sum[:])
			b, _ := json.Marshal(f.c)
			if err := os.WriteFile(filepath.Join(f.m.configDir, "demo.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			_, f.hash, _ = ReadConfig(b)
			candidate := Release{ID: "r-one", App: "demo", SHA: strings.Repeat("b", 40), Digest: "sha256:" + strings.Repeat("a", 64), ConfigSHA256: f.hash, RunID: 5}
			if kind == "ahead" || kind == "behind" || kind == "diverged" {
				old := f.approve("r-prev", 1, "")
				old.SHA = strings.Repeat("a", 40)
				s := State{Current: &Accepted{old, 1}, HighWater: 1}
				if err := f.m.save("demo", &s, "accepted"); err != nil {
					t.Fatal(err)
				}
				f.live = 1
			}
			if kind == "other-app" {
				candidate.App = "other"
			}
			if kind == "earlier-app-fails" {
				// An app polled earlier in name order whose repository the server token cannot read.
				other := f.c
				other.App, other.User, other.UID, other.Ports = "aaa", "app-aaa", 2002, [2]int{18083, 18084}
				other.Hostname, other.ImageRepo, other.GitHub.Repo = "aaa.example.test", "ghcr.io/example/aaa", "example/aaa"
				b, _ := json.Marshal(other)
				if err := os.WriteFile(filepath.Join(f.m.configDir, "aaa.json"), b, 0600); err != nil {
					t.Fatal(err)
				}
				lookup := f.m.lookupUser
				f.m.lookupUser = func(name string) (string, error) {
					if name == "app-aaa" {
						return "2002", nil
					}
					return lookup(name)
				}
			}
			if kind == "wrong-digest" {
				candidate.Digest = "latest"
			}
			if kind == "held" {
				s := State{Hold: true}
				if err := f.m.save("demo", &s, "held"); err != nil {
					t.Fatal(err)
				}
			}
			var callsMutex sync.Mutex
			var apiCalls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callsMutex.Lock()
				apiCalls = append(apiCalls, r.URL.Path)
				callsMutex.Unlock()
				if r.Method != "GET" {
					t.Error("provider mutation attempted", r.Method)
					http.Error(w, "method", 405)
					return
				}
				if r.Header.Get("Authorization") != "Bearer fixture" {
					t.Error("missing authenticated API read")
				}
				switch {
				case strings.HasPrefix(r.URL.Path, "/repos/example/aaa/"):
					http.Error(w, "not accessible", 404)
				case strings.HasSuffix(r.URL.Path, "/deployments"):
					creator := int64(42)
					if kind == "wrong-creator" {
						creator = 90
					}
					source := candidate.SHA
					if kind == "wrong-source" {
						source = strings.Repeat("a", 40)
					}
					signed := signedRelease{Release: candidate, Repository: "example/demo", Workflow: ".github/workflows/release.yml", RunAttempt: 1}
					if kind == "signed-wrong-repo" {
						signed.Repository = "other/repo"
					}
					raw, _ := json.Marshal(signed)
					sig := ed25519.Sign(private, raw)
					if kind == "forged-signature" {
						_, other, _ := ed25519.GenerateKey(rand.Reader)
						sig = ed25519.Sign(other, raw)
					}
					if kind == "changed-digest" {
						signed.Digest = "sha256:" + strings.Repeat("f", 64)
						raw, _ = json.Marshal(signed)
					}
					env := signedEnvelope{Body: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(sig)}
					if kind == "unsigned" {
						env.Signature = ""
					}
					task := "minimal-host"
					if kind == "automatic-environment" {
						task = "deploy"
					}
					entries := []any{map[string]any{"id": 99, "task": task, "sha": source, "environment": "production", "creator": map[string]any{"id": creator}, "payload": env}}
					if kind == "older-listed-first" {
						older := signed
						older.ID, older.RunID = "r-old", 4
						raw, _ := json.Marshal(older)
						env := signedEnvelope{Body: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))}
						entries = append([]any{map[string]any{"id": 98, "task": task, "sha": source, "environment": "production", "creator": map[string]any{"id": creator}, "payload": env}}, entries...)
					}
					json.NewEncoder(w).Encode(entries)
				case strings.Contains(r.URL.Path, "/actions/runs/"):
					status, conclusion, attempt := "completed", "success", 1
					if kind == "failed-run" {
						conclusion = "failure"
					}
					if kind == "pending-run" {
						status = "in_progress"
					}
					if kind == "rerun" {
						attempt = 2
					}
					json.NewEncoder(w).Encode(map[string]any{"id": 5, "head_sha": candidate.SHA, "head_branch": "main", "event": "push", "status": status, "conclusion": conclusion, "path": ".github/workflows/release.yml", "run_attempt": attempt, "repository": map[string]any{"full_name": "example/demo"}})
				case strings.Contains(r.URL.Path, "/git/ref/"):
					sha := candidate.SHA
					if kind == "old-branch" {
						sha = strings.Repeat("c", 40)
					}
					json.NewEncoder(w).Encode(map[string]any{"object": map[string]any{"sha": sha}})
				case strings.Contains(r.URL.Path, "/compare/"):
					// Like GitHub, the first page lists changed files with patches; a busy monorepo exceeds the read bound.
					if q := r.URL.Query(); q.Get("per_page") != "1" || q.Get("page") != "2" {
						json.NewEncoder(w).Encode(map[string]any{"status": kind, "files": []string{strings.Repeat("p", 1<<20)}})
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"status": kind})
				case strings.Contains(r.URL.Path, "/contents/"):
					text := workflow
					if kind == "changed-workflow" {
						text = []byte("attacker workflow")
					}
					if kind == "policy-changed-during-read" {
						next := f.c
						next.GitHub.WorkflowSHA256 = strings.Repeat("d", 64)
						path := filepath.Join(f.m.configDir, "reviewed-policy")
						if err := atomicJSON(path, next); err != nil {
							t.Error(err)
						} else if err := f.m.UpdateReleasePolicy(path); err != nil {
							t.Error(err)
						}
					}
					json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString(text)})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := NewGitHub("fixture")
			client.baseURL = server.URL
			err = f.m.Poll(context.Background(), client)
			switch kind {
			case "ok":
				if err != nil {
					t.Fatal(err)
				}
				s := f.state()
				if s.Current == nil || s.Current.Release.ID != "r-one" || s.HighWater != 5 {
					t.Fatal("approved request not accepted", s)
				}
				count := len(f.calls)
				callsMutex.Lock()
				apiCalls = nil
				callsMutex.Unlock()
				if err = f.m.Poll(context.Background(), client); err != nil {
					t.Fatal(err)
				}
				if len(f.calls) != count {
					t.Fatal("signed request replay caused native effects")
				}
				callsMutex.Lock()
				unchangedCalls := append([]string(nil), apiCalls...)
				callsMutex.Unlock()
				if len(unchangedCalls) != 1 || !strings.HasSuffix(unchangedCalls[0], "/deployments") {
					t.Fatal("accepted request rechecked expensive workflow endpoints", unchangedCalls)
				}
			case "ahead", "older-listed-first":
				if err != nil {
					t.Fatal(err)
				}
				if s := f.state(); s.Current == nil || s.Current.Release.ID != "r-one" || s.HighWater != 5 {
					t.Fatal("descendant release not accepted", s)
				}
			case "earlier-app-fails":
				if err == nil || !strings.HasPrefix(err.Error(), "aaa: ") {
					t.Fatal("earlier app failure not reported", err)
				}
				if s := f.state(); s.Current == nil || s.Current.Release.ID != "r-one" || s.HighWater != 5 {
					t.Fatal("earlier app failure blocked a later app's release", s)
				}
			case "wrong-creator", "pending-run", "held", "automatic-environment", "other-app":
				if err != nil {
					t.Fatal(err)
				}
				if len(f.calls) != 0 {
					t.Fatal("unauthorized, pending or held request executed")
				}
			default:
				if err == nil {
					t.Fatal("invalid request accepted")
				}
				if len(f.calls) != 0 {
					t.Fatal("invalid request caused native effects")
				}
			}
		})
	}
}

func TestOpenSSLReleaseSignatureInteroperability(t *testing.T) {
	binary, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is not installed on this test host")
	}
	version, err := exec.Command(binary, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(version, []byte("OpenSSL ")) {
		t.Skip("native signer contract requires OpenSSL, not LibreSSL")
	}
	directory := t.TempDir()
	private := filepath.Join(directory, "fixture.pem")
	bodyPath := filepath.Join(directory, "body.json")
	signaturePath := filepath.Join(directory, "signature.bin")
	run := func(args ...string) []byte {
		t.Helper()
		c := exec.Command(binary, args...)
		c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		data, err := c.Output()
		if err != nil {
			t.Fatal("OpenSSL fixture command failed", args[0], err)
		}
		return data
	}
	run("genpkey", "-algorithm", "ED25519", "-out", private)
	der := run("pkey", "-in", private, "-pubout", "-outform", "DER")
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("{\"id\":\"r-one\"}\n")
	if err = os.WriteFile(bodyPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	run("pkeyutl", "-sign", "-rawin", "-inkey", private, "-in", bodyPath, "-out", signaturePath)
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(signedEnvelope{Body: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(signature)})
	signed, err := decodeEnvelope(envelope)
	if err != nil || !ed25519.Verify(key.(ed25519.PublicKey), signed.raw, signed.signature) {
		t.Fatal("OpenSSL exact-byte signature does not interoperate", err)
	}
	if ed25519.Verify(key.(ed25519.PublicKey), bytes.TrimSpace(signed.raw), signed.signature) {
		t.Fatal("signed bytes were incorrectly normalized")
	}
}
