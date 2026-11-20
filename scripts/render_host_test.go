package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostStage(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "examples/demo.json"))
	if err != nil {
		t.Fatal(err)
	}
	var demo map[string]any
	if err = json.Unmarshal(raw, &demo); err != nil {
		t.Fatal(err)
	}
	demo["uid"] = 2001
	demo["github"].(map[string]any)["signing_public_key"] = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	other := make(map[string]any)
	for k, v := range demo {
		other[k] = v
	}
	other["app"], other["user"], other["uid"], other["hostname"], other["ports"] = "other", "app-other", 2002, "other.example.invalid", []int{18003, 18004}
	other["mounts"] = []any{}
	dir := t.TempDir()
	for name, c := range map[string]map[string]any{"demo": demo, "other": other} {
		b, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name+".json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	render := func(order, out string) error {
		c := exec.Command("go", "run", "./scripts/render-host.go", "--source", root, "--apps", order, "--proxy-image", "docker.io/library/caddy@sha256:"+strings.Repeat("a", 64), "--out", out)
		c.Dir = root
		b, e := c.CombinedOutput()
		if e != nil {
			t.Log(string(b))
		}
		return e
	}
	a, b := filepath.Join(dir, "demo.json"), filepath.Join(dir, "other.json")
	if err = render(a+","+b, filepath.Join(dir, "one")); err != nil {
		t.Fatal(err)
	}
	if err = render(b+","+a, filepath.Join(dir, "two")); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"one", "two"} {
		subids, e := os.ReadFile(filepath.Join(dir, stage, "subids"))
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range []string{"host-proxy:2000000:65536", "app-demo:2196608:65536", "app-other:2262144:65536"} {
			if !strings.Contains(string(subids), entry+"\n") {
				t.Fatalf("UID-derived range absent: %s", subids)
			}
		}
		accounts, e := os.ReadFile(filepath.Join(dir, stage, "accounts.tsv"))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(accounts), "core") {
			t.Fatal("renderer must not create administrator")
		}
		enabled, e := os.ReadFile(filepath.Join(dir, stage, "enabled.txt"))
		if e != nil {
			t.Fatal(e)
		}
		for _, forbidden := range []string{"timer", "firewall", "tailscale", "enrollment"} {
			if strings.Contains(string(enabled), forbidden) {
				t.Fatalf("unsafe default activation: %s", enabled)
			}
		}
		unit, e := os.ReadFile(filepath.Join(dir, stage, "root/etc/systemd/system/minimal-host-reconcile.service"))
		if e != nil {
			t.Fatal(e)
		}
		for _, dependency := range []string{"user@1998.service", "user@2001.service", "user@2002.service"} {
			if !strings.Contains(string(unit), dependency) {
				t.Fatal("missing user dependency", dependency)
			}
		}
		if !strings.Contains(string(unit), "Requires=user@1998.service\n") || !strings.Contains(string(unit), "Wants=network-online.target user@") {
			t.Fatal("an unavailable app user manager must leave other apps eligible for boot recovery")
		}
		for _, name := range []string{"minimal-host-helper@.service", "minimal-host-poll.service"} {
			unit, e := os.ReadFile(filepath.Join(dir, stage, "root/etc/systemd/system", name))
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(unit), "ProtectControlGroups=yes") {
				t.Fatal("missing delegated cgroup boundary", name)
			}
			if name == "minimal-host-poll.service" {
				for _, setting := range []string{"Requires=minimal-host-binaries.service\n", "After=minimal-host-binaries.service network-online.target minimal-host-reconcile.service\n", "-/run/user/2001 -/var/home/app-demo", "-/run/user/2002 -/var/home/app-other"} {
					if !strings.Contains(string(unit), setting) {
						t.Fatal("poll must wait for boot recovery, then start even if an app runtime path is missing", setting)
					}
				}
			}
		}
		for _, uid := range []string{"2001", "2002"} {
			unit, e := os.ReadFile(filepath.Join(dir, stage, "root/etc/systemd/system/user@"+uid+".service.d/minimal-host.conf"))
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(unit), "XDG_RUNTIME_DIR=/run/user/"+uid+" /usr/bin/podman unshare /usr/bin/true") {
				t.Fatal("rootless namespace must initialize at user manager startup")
			}
		}
	}
	if render(a+","+a, filepath.Join(dir, "duplicate")) == nil {
		t.Fatal("duplicate identity accepted")
	}
	if render(a, filepath.Join(dir, "one")) == nil {
		t.Fatal("existing stage overwritten")
	}
}
