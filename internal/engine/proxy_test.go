package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestProxyClientDrivesTheInstalledRoute(t *testing.T) {
	f := setup(t, "overlap")
	route := ProxyRoute(f.c)
	if handler := route["handle"].([]any)[0].(map[string]any); handler["handler"] != "reverse_proxy" {
		t.Fatal("promotion addresses handle 0, which is not the reverse proxy", route)
	}
	dir, err := os.MkdirTemp("", "caddy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.m.caddySocket = filepath.Join(dir, "admin.sock")
	listener, err := net.Listen("unix", f.m.caddySocket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	upstreams, rejectPatch := "[]", false
	path := "/id/" + route["@id"].(string) + "/handle/0/upstreams"
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		if r.Method == "PATCH" {
			if rejectPatch {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			b, _ := io.ReadAll(r.Body)
			upstreams = string(b)
			return
		}
		io.WriteString(w, upstreams)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	ctx := context.Background()
	for _, slot := range []int{2, 0, 1} {
		if err := f.m.route(ctx, f.c, slot); err != nil {
			t.Fatal(err)
		}
		if live, err := f.m.liveRoute(ctx, f.c); err != nil || live != slot {
			t.Fatal("route readback", slot, live, err)
		}
	}
	for _, bad := range []string{`[{"dial":"127.0.0.1:9"}]`, `[{"dial":"127.0.0.1:18081"},{"dial":"127.0.0.1:18082"}]`} {
		mu.Lock()
		upstreams = bad
		mu.Unlock()
		if _, err := f.m.liveRoute(ctx, f.c); err == nil || errors.Is(err, errProxyUnavailable) {
			t.Fatal("route outside policy accepted or mistaken for startup", bad, err)
		}
	}
	mu.Lock()
	rejectPatch = true
	mu.Unlock()
	if err := f.m.route(ctx, f.c, 1); err == nil {
		t.Fatal("rejected route update reported as success")
	}
	server.Close()
	if _, err := f.m.liveRoute(ctx, f.c); !errors.Is(err, errProxyUnavailable) {
		t.Fatal("stopped proxy not reported unavailable", err)
	}
}
