//go:build ignore

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"minimal.host/platform/internal/engine"
)

type file struct {
	path string
	mode int
	data []byte
}
type dir struct {
	path           string
	mode, uid, gid int
}
type account struct {
	uid  int
	name string
}
type unit struct {
	name     string
	enabled  bool
	contents string
}
type object = map[string]any

const proxyUID, mcpUID = 1998, 1999

// Each account's subordinate range follows its UID, so no two ranges overlap.
func subidStart(uid int) int { return 2000000 + (uid-proxyUID)*65536 }

func main() {
	source := flag.String("source", "", "absolute hosting source directory")
	appFiles := flag.String("apps", "", "comma-separated absolute app manifest paths")
	proxyImage := flag.String("proxy-image", "", "Caddy OCI repository@sha256:digest")
	rootfs := flag.String("out", "", "new absolute host staging directory")
	dnsResolvers := flag.String("dns-resolvers", "", "explicit comma-separated literal resolver IPs permitted on UDP/TCP53 for app/proxy UIDs")
	flag.Parse()
	fail := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if !filepath.IsAbs(*source) || !filepath.IsAbs(*rootfs) || *appFiles == "" {
		fail(fmt.Errorf("absolute source/output and app manifests are required"))
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.:/_-]+@sha256:[a-f0-9]{64}$`).MatchString(*proxyImage) {
		fail(fmt.Errorf("digest-pinned Caddy image required"))
	}
	dnsRules := []string{}
	seenResolvers := map[netip.Addr]bool{}
	if *dnsResolvers != "" {
		for _, value := range strings.Split(*dnsResolvers, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(value))
			fail(err)
			if addr.Zone() != "" {
				fail(fmt.Errorf("scoped resolver literals are unsupported"))
			}
			addr = addr.Unmap()
			if addr.IsUnspecified() || addr.IsMulticast() || !(addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast()) {
				fail(fmt.Errorf("resolver must be an unscoped unicast literal IP"))
			}
			if seenResolvers[addr] {
				continue
			}
			seenResolvers[addr] = true
			family := "ip"
			if addr.Is6() {
				family = "ip6"
			}
			for _, uid := range []string{fmt.Sprint(proxyUID), fmt.Sprintf("%d-%d", engine.MinAppUID, engine.MaxAppUID)} {
				for _, transport := range []string{"udp", "tcp"} {
					dnsRules = append(dnsRules, fmt.Sprintf("    meta skuid %s %s daddr %s %s dport 53 accept", uid, family, addr.String(), transport))
				}
			}
		}
	}
	accounts := []account{{proxyUID, "host-proxy"}, {mcpUID, "host-mcp"}}
	var files []file
	var dirs []dir
	add := func(path string, mode int, data []byte) { files = append(files, file{path, mode, data}) }
	mkdir := func(path string, mode, uid, gid int) { dirs = append(dirs, dir{path, mode, uid, gid}) }
	read := func(path string) []byte { b, e := os.ReadFile(filepath.Join(*source, path)); fail(e); return b }
	subids := fmt.Sprintf("host-proxy:%d:65536\n", subidStart(proxyUID))
	tmpfiles := "d /run/minimal-host 0755 root root -\nd /run/minimal-host/proxy 0700 host-proxy host-proxy -\nf " + engine.LockPath + " 0600 root root -\n"
	routes := []any{}
	hosts := []string{}
	seenUsers, seenUIDs, seenPorts, seenHosts := map[string]bool{}, map[int]bool{}, map[int]bool{}, map[string]bool{}
	appUnits := []string{}
	appRWPaths := []string{}
	for _, path := range strings.Split(*appFiles, ",") {
		if !filepath.IsAbs(path) {
			fail(fmt.Errorf("manifest paths must be absolute"))
		}
		b, e := os.ReadFile(path)
		fail(e)
		c, _, e := engine.ReadConfig(b)
		fail(e)
		if seenUsers[c.User] || seenUIDs[c.UID] || seenHosts[c.Hostname] {
			fail(fmt.Errorf("app users, UIDs and hostnames must be unique"))
		}
		seenUsers[c.User], seenUIDs[c.UID], seenHosts[c.Hostname] = true, true, true
		for _, p := range c.Ports {
			if seenPorts[p] {
				fail(fmt.Errorf("proxy backend ports must be unique"))
			}
			seenPorts[p] = true
		}
		accounts = append(accounts, account{c.UID, c.User})
		subids += fmt.Sprintf("%s:%d:65536\n", c.User, subidStart(c.UID))
		add("/var/lib/systemd/linger/"+c.User, 0644, nil)
		quadlets := fmt.Sprintf("%s/%d", engine.QuadletRoot, c.UID)
		add(quadlets+"/"+c.Network()+".network", 0644, []byte("[Network]\nNetworkName="+c.Network()+"\nDriver=bridge\n"))
		add(engine.ConfigDir+"/"+c.App+".json", 0644, b)
		add(fmt.Sprintf("/etc/systemd/system/user@%d.service.d/minimal-host.conf", c.UID), 0644, []byte(fmt.Sprintf("[Service]\nExecStartPost=/usr/bin/env HOME=%s XDG_RUNTIME_DIR=/run/user/%d /usr/bin/podman unshare /usr/bin/true\n", c.Home(), c.UID)))
		add("/etc/minimal-host/backup/"+c.App+".env", 0644, []byte(fmt.Sprintf("APP_USER=%s\nAPP_UID=%d\n", c.User, c.UID)))
		for _, p := range []string{c.Home(), c.DataDir(), c.DataDir() + "/data"} {
			mkdir(p, 0700, c.UID, c.UID)
		}
		mkdir(quadlets, 0755, 0, 0)
		mkdir(c.SecretDir(), 0710, 0, c.UID)
		hosts = append(hosts, c.Hostname)
		routes = append(routes, engine.ProxyRoute(c))
		appUnits = append(appUnits, fmt.Sprintf("user@%d.service", c.UID))
		appRWPaths = append(appRWPaths, fmt.Sprintf("/run/user/%d", c.UID), c.Home())
	}
	add("/var/lib/systemd/linger/host-proxy", 0644, nil)
	for _, p := range []string{engine.ConfigDir, "/etc/minimal-host/backup", "/etc/minimal-host/proxy", fmt.Sprintf("%s/%d", engine.QuadletRoot, proxyUID), "/usr/local/libexec"} {
		mkdir(p, 0755, 0, 0)
	}
	for _, p := range []string{"/etc/minimal-host/secrets", "/etc/minimal-host/secrets/backup", engine.StateDir, engine.ApprovalDir} {
		mkdir(p, 0700, 0, 0)
	}
	mkdir("/var/lib/minimal-host", 0755, 0, 0)
	mkdir("/var/home/host-proxy", 0700, proxyUID, proxyUID)
	mkdir("/var/home/host-mcp", 0700, mcpUID, mcpUID)
	for _, p := range []string{"/var/lib/minimal-host/proxy", "/var/lib/minimal-host/proxy/data", "/var/lib/minimal-host/proxy/config"} {
		mkdir(p, 0700, proxyUID, proxyUID)
	}
	add("/etc/tmpfiles.d/minimal-host.conf", 0644, []byte(tmpfiles))
	add("/etc/dnf/automatic.conf", 0644, read("infra/host/automatic.conf"))
	add("/etc/systemd/system/dnf5-automatic.service.d/minimal-host.conf", 0644, read("infra/host/dnf5-automatic.service.conf"))
	add("/etc/systemd/system/dnf5-automatic.timer.d/minimal-host.conf", 0644, read("infra/host/dnf5-automatic.timer.conf"))
	add("/etc/minimal-host/firewall.nft", 0644, []byte(strings.ReplaceAll(string(read("infra/host/firewall.nft")), "@DNS_RULES@", strings.Join(dnsRules, "\n"))))
	add(fmt.Sprintf("%s/%d/host-proxy.container", engine.QuadletRoot, proxyUID), 0644, []byte(strings.ReplaceAll(string(read("infra/proxy/host-proxy.container")), "@PROXY_IMAGE@", *proxyImage)))
	proxy := object{"admin": object{"listen": "unix//run/caddy/admin.sock"}, "storage": object{"module": "file_system", "root": "/data"}, "apps": object{"http": object{"http_port": 8080, "https_port": 8443, "servers": object{"https": object{"listen": []string{":8443"}, "protocols": []string{"h1", "h2"}, "automatic_https": object{"disable_redirects": true}, "tls_connection_policies": []object{{}}, "routes": routes}, "redirect": object{"listen": []string{":8080"}, "routes": []object{{"match": []object{{"host": hosts}}, "handle": []object{{"handler": "static_response", "status_code": 308, "headers": object{"Location": []string{"https://{http.request.host}{http.request.uri}"}}}}}}}}}}}
	pb, e := json.Marshal(proxy)
	fail(e)
	add("/etc/minimal-host/proxy/config.json", 0644, pb)
	for _, name := range []string{"minimal-host-binaries", "minimal-host-backup", "minimal-host-health", "install-secret"} {
		add("/usr/local/libexec/"+name, 0755, read("scripts/"+name))
	}
	entries, e := os.ReadDir(filepath.Join(*source, "infra/systemd"))
	fail(e)
	enabled := map[string]bool{"minimal-host-binaries.service": true, "minimal-host-helper.socket": true, "minimal-host-mcp.service": true, "minimal-host-reconcile.service": true}
	var units []unit
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		text := string(read("infra/systemd/" + name))
		text = strings.ReplaceAll(text, "@APP_RW_PATHS@", strings.Join(appRWPaths, " "))
		text = strings.ReplaceAll(text, "@APP_OPTIONAL_RW_PATHS@", "-"+strings.Join(appRWPaths, " -"))
		text = strings.ReplaceAll(text, "@APP_USER_UNITS@", strings.Join(appUnits, " "))
		units = append(units, unit{name, enabled[name], text})
	}
	fail(os.Mkdir(*rootfs, 0700))
	write := func(path string, mode int, b []byte) {
		p := filepath.Join(*rootfs, "root", path)
		fail(os.MkdirAll(filepath.Dir(p), 0755))
		fail(os.WriteFile(p, b, os.FileMode(mode)))
	}
	var metadata strings.Builder
	for _, f := range files {
		write(f.path, f.mode, f.data)
		fmt.Fprintf(&metadata, "%o\t%s\n", f.mode, f.path)
	}
	for _, u := range units {
		path := "/etc/systemd/system/" + u.name
		write(path, 0644, []byte(u.contents))
		fmt.Fprintf(&metadata, "644\t%s\n", path)
	}
	fail(os.WriteFile(filepath.Join(*rootfs, "files.tsv"), []byte(metadata.String()), 0600))
	metadata.Reset()
	for _, d := range dirs {
		fmt.Fprintf(&metadata, "%o\t%d\t%d\t%s\n", d.mode, d.uid, d.gid, d.path)
	}
	fail(os.WriteFile(filepath.Join(*rootfs, "dirs.tsv"), []byte(metadata.String()), 0600))
	metadata.Reset()
	for _, a := range accounts {
		fmt.Fprintf(&metadata, "%d\t%s\n", a.uid, a.name)
	}
	fail(os.WriteFile(filepath.Join(*rootfs, "accounts.tsv"), []byte(metadata.String()), 0600))
	fail(os.WriteFile(filepath.Join(*rootfs, "subids"), []byte(subids), 0600))
	metadata.Reset()
	for _, u := range units {
		if u.enabled {
			fmt.Fprintln(&metadata, u.name)
		}
	}
	fail(os.WriteFile(filepath.Join(*rootfs, "enabled.txt"), []byte(metadata.String()), 0600))
}
