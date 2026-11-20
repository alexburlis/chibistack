package mcpgate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"minimal.host/platform/internal/protocol"
)

const readerCaps = `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["status"]}]}`
const allCaps = `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["status","deployment_status","logs","health","deploy","rollback"]}]}`

func TestCapabilityGrammar(t *testing.T) {
	tests := map[string]string{
		"empty": "", "empty object": "{}", "empty grants": `{"minimal.host/capabilities":[]}`,
		"null grant":            `{"minimal.host/capabilities":[null]}`,
		"unknown capability":    `{"other":[{}]}`,
		"other capability":      `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["status"]}],"other":[]}`,
		"duplicate capability":  `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["status"]}],"minimal.host/capabilities":[{"apps":["demo"],"ops":["rollback"]}]}`,
		"unknown grant field":   `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["status"],"all":true}]}`,
		"duplicate grant field": `{"minimal.host/capabilities":[{"apps":["other"],"apps":["demo"],"ops":["status"]}]}`,
		"wildcard app":          `{"minimal.host/capabilities":[{"apps":["*"],"ops":["status"]}]}`,
		"shell app":             `{"minimal.host/capabilities":[{"apps":["demo;id"],"ops":["status"]}]}`,
		"unknown op":            `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["exec"]}]}`,
		"missing ops":           `{"minimal.host/capabilities":[{"apps":["demo"]}]}`,
		"duplicate app":         `{"minimal.host/capabilities":[{"apps":["demo","demo"],"ops":["status"]}]}`,
		"duplicate op":          `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["status","status"]}]}`,
		"trailing value":        readerCaps + `{}`, "too large": readerCaps + strings.Repeat(" ", 8193-len(readerCaps)),
	}
	for name, s := range tests {
		t.Run(name, func(t *testing.T) {
			h := http.Header{}
			h.Set("Tailscale-App-Capabilities", s)
			if _, err := capabilities(h); err == nil {
				t.Fatal("invalid capability accepted")
			}
		})
	}
	h := http.Header{}
	h.Add("Tailscale-App-Capabilities", readerCaps)
	h.Add("Tailscale-App-Capabilities", readerCaps)
	if _, err := capabilities(h); err == nil {
		t.Fatal("duplicate header accepted")
	}
	h.Set("Tailscale-App-Capabilities", readerCaps)
	grants, err := capabilities(h)
	if err != nil || !allowed(grants, "demo", "status") || allowed(grants, "demo", "rollback") {
		t.Fatal("wrong valid grant", err)
	}
}

func TestForwardedIdentity(t *testing.T) {
	for _, v := range []string{"100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1234"} {
		h := http.Header{}
		h.Set("X-Forwarded-For", v)
		if !forwardedPeer(h) {
			t.Fatal("tailnet rejected", v)
		}
	}
	for _, v := range []string{"", "127.0.0.1", "192.168.1.2", "8.8.8.8", "::1", "100.128.0.1", "100.64.0.1, 100.64.0.2", "100.64.0.1:8080", "::ffff:100.64.0.1", "100.64.0.1%eth0"} {
		h := http.Header{}
		h.Set("X-Forwarded-For", v)
		if forwardedPeer(h) {
			t.Fatal("non-tailnet identity accepted", v)
		}
	}
	h := http.Header{}
	h.Add("X-Forwarded-For", "100.64.0.1")
	h.Add("X-Forwarded-For", "100.64.0.2")
	if forwardedPeer(h) {
		t.Fatal("duplicate identity accepted")
	}
}

func request(h http.Handler, body, caps string, root bool, edit func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-06-18")
	r.Header.Set("Tailscale-App-Capabilities", caps)
	r.Header.Set("X-Forwarded-For", "100.64.0.2")
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, root))
	if edit != nil {
		edit(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func rpc(method, params string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `}`
}
func call(name, args string) string {
	return rpc("tools/call", `{"name":"`+name+`","arguments":`+args+`}`)
}

type reply struct {
	Result struct {
		Tools             []struct{ Name string }
		IsError           bool
		StructuredContent json.RawMessage
	}
	Error *struct {
		Code    int
		Message string
	}
}

func decode(t *testing.T, w *httptest.ResponseRecorder) reply {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var r reply
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err, w.Body.String())
	}
	return r
}

func TestToolsAndSameGrantAuthorization(t *testing.T) {
	var calls []protocol.Request
	h := endpoint(func(_ context.Context, r protocol.Request) (json.RawMessage, error) {
		calls = append(calls, r)
		return json.RawMessage(`{"state":"healthy"}`), nil
	})
	list := decode(t, request(h, rpc("tools/list", `{}`), readerCaps, true, nil))
	if len(list.Result.Tools) != 1 || list.Result.Tools[0].Name != "status" {
		t.Fatal("reader discovery escaped", list)
	}
	r := decode(t, request(h, call("status", `{"app":"demo"}`), readerCaps, true, nil))
	if r.Error != nil || r.Result.IsError || string(r.Result.StructuredContent) != `{"state":"healthy"}` {
		t.Fatalf("permitted status failed: result=%+v error=%+v", r.Result, r.Error)
	}
	if !reflect.DeepEqual(calls, []protocol.Request{{Op: "status", App: "demo"}}) {
		t.Fatal(calls)
	}
	calls = nil
	cross := `{"minimal.host/capabilities":[{"apps":["demo"],"ops":["status"]},{"apps":["other"],"ops":["rollback"]}]}`
	for _, tc := range []struct{ name, body, caps string }{
		{"undiscovered mutation", call("rollback", `{"app":"demo"}`), readerCaps},
		{"foreign app", call("status", `{"app":"other"}`), readerCaps},
		{"cross-grant", call("rollback", `{"app":"demo"}`), cross},
		{"extra field", call("status", `{"app":"demo","command":"id"}`), readerCaps},
		{"unapproved argument shape", call("deploy", `{"app":"demo","release":"../other"}`), allCaps},
		{"missing release", call("deploy", `{"app":"demo"}`), allCaps},
		{"wrong release verb", call("rollback", `{"app":"demo","release":"abc"}`), allCaps},
		{"unknown tool", call("exec", `{"app":"demo"}`), allCaps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := decode(t, request(h, tc.body, tc.caps, true, nil))
			if r.Error == nil && !r.Result.IsError {
				t.Fatal("forbidden call succeeded", r)
			}
			if len(calls) != 0 {
				t.Fatal("forbidden call reached helper", calls)
			}
		})
	}
	r = decode(t, request(h, call("deploy", `{"app":"demo","release":"r-42527018010"}`), allCaps, true, nil))
	if r.Error != nil || r.Result.IsError || len(calls) != 1 || calls[0].Release != "r-42527018010" {
		t.Fatal("approved release request lost", r, calls)
	}
}

func TestRequestAuthenticationAndOrigin(t *testing.T) {
	h := endpoint(func(context.Context, protocol.Request) (json.RawMessage, error) {
		t.Fatal("unauthenticated helper call")
		return nil, nil
	})
	for _, tc := range []struct {
		name string
		root bool
		caps string
		edit func(*http.Request)
	}{
		{"non-root peer", false, allCaps, nil},
		{"missing cap", true, "", nil},
		{"duplicate cap", true, allCaps, func(r *http.Request) { r.Header.Add("Tailscale-App-Capabilities", allCaps) }},
		{"missing identity", true, allCaps, func(r *http.Request) { r.Header.Del("X-Forwarded-For") }},
		{"local-origin peer", true, allCaps, func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }},
		{"cross origin", true, allCaps, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }},
		{"cross-site browser", true, allCaps, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(h, rpc("tools/list", `{}`), tc.caps, tc.root, tc.edit)
			if w.Code != 403 {
				t.Fatal("not forbidden", w.Code, w.Body.String())
			}
		})
	}
}

func TestRevocationAndBodyBound(t *testing.T) {
	calls := 0
	h := endpoint(func(context.Context, protocol.Request) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{}`), nil
	})
	r := decode(t, request(h, call("status", `{"app":"demo"}`), readerCaps, true, nil))
	if r.Error != nil || r.Result.IsError || calls != 1 {
		t.Fatalf("initial permission failed: result=%+v error=%+v", r.Result, r.Error)
	}
	w := request(h, call("status", `{"app":"demo"}`), `{}`, true, nil)
	if w.Code != 403 || calls != 1 {
		t.Fatal("revoked grant reused")
	}
	w = request(h, strings.Repeat(" ", 8193)+call("status", `{"app":"demo"}`), readerCaps, true, nil)
	if w.Code < 400 || calls != 1 {
		t.Fatal("oversized body accepted", w.Code)
	}
}

func TestHelperResponseBoundAndRedaction(t *testing.T) {
	good, err := readResponse(strings.NewReader(`{"ok":true,"data":{"state":"healthy"}}`))
	if err != nil || string(good) != `{"state":"healthy"}` {
		t.Fatal(good, err)
	}
	for _, s := range []string{
		`{"ok":false,"error":"private secret body"}`,
		`{"ok":true,"data":{},"error":"private secret body"}`,
		`{"ok":true,"data":{},"extra":1}`, `{"ok":true}`, `{`,
		`{"ok":true,"data":{}}{}`, `{"ok":true,"data":{}}` + strings.Repeat(" ", protocol.MaxFrame+1-len(`{"ok":true,"data":{}}`)),
	} {
		_, err := readResponse(strings.NewReader(s))
		if err == nil || strings.Contains(err.Error(), "private secret body") {
			t.Fatal("unsafe helper response", err)
		}
	}
	if _, err := readResponse(errorReader{}); err == nil || strings.Contains(err.Error(), "private io body") {
		t.Fatal("raw transport error leaked", err)
	}
	_, err = helper(filepath.Join(t.TempDir(), "absent"))(context.Background(), protocol.Request{Op: "status", App: "demo"})
	if err == nil || strings.Contains(err.Error(), "absent") {
		t.Fatal("raw socket error leaked", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("private io body") }

func TestRunRequiresSupportedUnprivilegedRuntime(t *testing.T) {
	if !peerCredentialsSupported() || os.Geteuid() == 0 {
		if err := Run(context.Background(), "/missing/http.sock", "/missing/helper.sock"); err == nil {
			t.Fatal("unsupported/root runtime accepted")
		}
	}
	if rootPeer(&net.TCPConn{}) {
		t.Fatal("TCP has root peer authority")
	}
}

func TestReadOnlyAnnotations(t *testing.T) {
	h := endpoint(func(context.Context, protocol.Request) (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
	w := request(h, rpc("tools/list", `{}`), allCaps, true, nil)
	var list struct {
		Result struct {
			Tools []struct {
				Name        string
				Annotations struct{ ReadOnlyHint bool }
			}
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range list.Result.Tools {
		got[tool.Name] = tool.Annotations.ReadOnlyHint
	}
	want := map[string]bool{"status": true, "deployment_status": true, "logs": true, "health": true, "overview": true, "deploy": false, "rollback": false}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestOverviewReadsEachGrantedAppIndependently(t *testing.T) {
	caps := `{"minimal.host/capabilities":[{"apps":["demo","other"],"ops":["deployment_status","health"]},{"apps":["logsonly"],"ops":["logs"]},{"apps":["other","third"],"ops":["deployment_status"]}]}`
	var mu sync.Mutex
	var calls []protocol.Request
	h := endpoint(func(_ context.Context, r protocol.Request) (json.RawMessage, error) {
		mu.Lock()
		calls = append(calls, r)
		mu.Unlock()
		if r.App == "third" {
			return nil, errors.New("private helper detail")
		}
		return json.RawMessage(`{"op":"` + r.Op + `"}`), nil
	})
	if list := decode(t, request(h, rpc("tools/list", `{}`), readerCaps, true, nil)); slices.ContainsFunc(list.Result.Tools, func(tool struct{ Name string }) bool { return tool.Name == "overview" }) {
		t.Fatal("overview discovered without deployment_status")
	}
	r := decode(t, request(h, call("overview", `{}`), caps, true, nil))
	if r.Error != nil || r.Result.IsError {
		t.Fatalf("overview failed: %+v %+v", r.Result, r.Error)
	}
	want := `{"apps":[` +
		`{"app":"demo","deployment":{"op":"deployment_status"},"health":{"op":"health"},"error":null},` +
		`{"app":"other","deployment":{"op":"deployment_status"},"health":{"op":"health"},"error":null},` +
		`{"app":"third","deployment":null,"health":null,"error":"deployment status unavailable"}]}`
	var got, expected any
	if json.Unmarshal(r.Result.StructuredContent, &got) != nil || json.Unmarshal([]byte(want), &expected) != nil || !reflect.DeepEqual(got, expected) {
		t.Fatal(string(r.Result.StructuredContent))
	}
	if len(calls) != 5 || slices.ContainsFunc(calls, func(c protocol.Request) bool { return c.App == "logsonly" || c.Op == "logs" }) {
		t.Fatal("overview read outside its grant", calls)
	}
	calls = nil
	if r := decode(t, request(h, call("overview", `{"app":"demo"}`), caps, true, nil)); r.Error == nil && !r.Result.IsError {
		t.Fatal("overview accepted arguments")
	}
	if len(calls) != 0 {
		t.Fatal("rejected overview reached helper", calls)
	}
}

func TestOverviewBoundsHelperConnections(t *testing.T) {
	var apps []string
	for i := range 12 {
		apps = append(apps, `"app`+string(rune('a'+i))+`"`)
	}
	caps := `{"minimal.host/capabilities":[{"apps":[` + strings.Join(apps, ",") + `],"ops":["deployment_status","health"]}]}`
	var mu sync.Mutex
	active, peak := 0, 0
	h := endpoint(func(context.Context, protocol.Request) (json.RawMessage, error) {
		mu.Lock()
		active++
		peak = max(peak, active)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		return json.RawMessage(`{}`), nil
	})
	if r := decode(t, request(h, call("overview", `{}`), caps, true, nil)); r.Error != nil || r.Result.IsError {
		t.Fatal("overview failed", r)
	}
	if peak < 2 || peak > overviewParallel {
		t.Fatalf("peak helper connections %d, want 2..%d", peak, overviewParallel)
	}
}
