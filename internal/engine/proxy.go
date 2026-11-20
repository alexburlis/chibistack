package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var errProxyUnavailable = errors.New("proxy route unavailable")

func routeID(c Config) string { return "app-" + c.App }

// ProxyRoute is the app's Caddy route as installed by render-host. Promotion
// rewrites the upstreams of its first handler, so the two must stay together.
func ProxyRoute(c Config) map[string]any {
	handler := map[string]any{"handler": "reverse_proxy", "upstreams": []any{}, "flush_interval": -1, "stream_close_delay": int64(c.DrainSeconds) * int64(time.Second)}
	return map[string]any{"@id": routeID(c), "match": []any{map[string]any{"host": []string{c.Hostname}}}, "handle": []any{handler}, "terminal": true}
}

func (m *Manager) upstreams(ctx context.Context, c Config, method string, body io.Reader) (*http.Response, func(), error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", m.caddySocket)
	}}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/id/"+routeID(c)+"/handle/0/upstreams", body)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	return resp, func() { resp.Body.Close(); transport.CloseIdleConnections() }, nil
}

// route points the app at a slot's backend, or at nothing for slot 0.
func (m *Manager) route(ctx context.Context, c Config, slot int) error {
	body := "[]"
	if slot != 0 {
		body = fmt.Sprintf(`[{"dial":%q}]`, c.backend(slot))
	}
	resp, done, err := m.upstreams(ctx, c, "PATCH", strings.NewReader(body))
	if err != nil {
		return errors.New("proxy promotion outcome uncertain")
	}
	defer done()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("proxy rejected route update")
	}
	return nil
}

// liveRoute reads which slot the proxy serves, 0 for none.
func (m *Manager) liveRoute(ctx context.Context, c Config) (int, error) {
	resp, done, err := m.upstreams(ctx, c, "GET", nil)
	if err != nil {
		return 0, errProxyUnavailable
	}
	defer done()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusServiceUnavailable {
		return 0, errProxyUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("proxy rejected route inspection")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return 0, errors.New("invalid proxy route response")
	}
	var upstreams []struct {
		Dial string `json:"dial"`
	}
	if json.Unmarshal(data, &upstreams) != nil || len(upstreams) > 1 {
		return 0, errors.New("invalid proxy route state")
	}
	if len(upstreams) == 0 {
		return 0, nil
	}
	for slot := 1; slot <= 2; slot++ {
		if upstreams[0].Dial == c.backend(slot) {
			return slot, nil
		}
	}
	return 0, errors.New("proxy route is outside installed application policy")
}

// waitProxy waits for the proxy, which starts asynchronously at boot.
func (m *Manager) waitProxy(ctx context.Context, c Config) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		slot, err := m.routeSlot(ctx, c)
		if err == nil {
			return slot, nil
		}
		if !errors.Is(err, errProxyUnavailable) {
			return 0, err
		}
		if delay(ctx, 100*time.Millisecond) != nil {
			return 0, fmt.Errorf("proxy readiness timed out or interrupted: %w", errProxyUnavailable)
		}
	}
}
