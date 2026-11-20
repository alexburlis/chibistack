// Package mcpgate exposes the installed lifecycle verbs through a private Unix socket.
package mcpgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"minimal.host/platform/internal/protocol"
)

const capability = "minimal.host/capabilities"

// The helper socket accepts at most 8 connections; overview leaves room for other callers.
const overviewParallel = 4
const overviewTimeout = 60 * time.Second

// helperTimeout bounds how long a tool waits; a longer operation continues and
// the caller reads deployment status.
const helperTimeout = 65 * time.Second

var tailnet4 = netip.MustParsePrefix("100.64.0.0/10")
var tailnet6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

type peerKey struct{}
type grant struct {
	Apps []string `json:"apps"`
	Ops  []string `json:"ops"`
}
type input struct {
	App     string `json:"app"`
	Release string `json:"release,omitempty"`
}
type forwardFunc func(context.Context, protocol.Request) (json.RawMessage, error)

func (g *grant) UnmarshalJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return errors.New("invalid grant")
	}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		name, ok := t.(string)
		if err != nil || !ok || seen[name] {
			return errors.New("invalid grant field")
		}
		seen[name] = true
		var values []string
		if err := d.Decode(&values); err != nil || len(values) == 0 || len(values) > 32 {
			return errors.New("invalid grant values")
		}
		for i, v := range values {
			_, known := protocol.Lookup(v)
			if (name == "apps" && !protocol.ValidName(v)) || (name == "ops" && !known) || slices.Contains(values[:i], v) {
				return errors.New("invalid grant value")
			}
		}
		switch name {
		case "apps":
			g.Apps = values
		case "ops":
			g.Ops = values
		default:
			return errors.New("unknown grant field")
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || len(seen) != 2 || d.Decode(new(any)) != io.EOF {
		return errors.New("incomplete grant")
	}
	return nil
}

func capabilities(h http.Header) ([]grant, error) {
	values := h.Values("Tailscale-App-Capabilities")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 8192 {
		return nil, errors.New("missing capabilities")
	}
	d := json.NewDecoder(strings.NewReader(values[0]))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') || !d.More() {
		return nil, errors.New("invalid capabilities")
	}
	t, err = d.Token()
	if err != nil || t != capability {
		return nil, errors.New("unknown capability")
	}
	var grants []grant
	if d.Decode(&grants) != nil || len(grants) == 0 || len(grants) > 32 || d.More() {
		return nil, errors.New("invalid grants")
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid capabilities")
	}
	return grants, nil
}

func allowed(grants []grant, app, op string) bool {
	for _, g := range grants {
		if slices.Contains(g.Apps, app) && slices.Contains(g.Ops, op) {
			return true
		}
	}
	return false
}

func forwardedPeer(h http.Header) bool {
	values := h.Values("X-Forwarded-For")
	if len(values) != 1 {
		return false
	}
	ip, err := netip.ParseAddr(values[0])
	return err == nil && (tailnet4.Contains(ip) || tailnet6.Contains(ip))
}

func endpoint(forward forwardFunc) http.Handler {
	origin := http.NewCrossOriginProtection()
	return origin.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		grants, err := capabilities(r.Header)
		if r.Context().Value(peerKey{}) != true || !forwardedPeer(r.Header) || err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		server := mcp.NewServer(&mcp.Implementation{Name: "chibistack", Version: "0.1.0"}, nil)
		for _, op := range protocol.Ops {
			if !slices.ContainsFunc(grants, func(g grant) bool { return slices.Contains(g.Ops, op.Name) }) {
				continue
			}
			mcp.AddTool(server, &mcp.Tool{Name: op.Name, Description: op.Name + " an authorized application", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: op.ReadOnly}, InputSchema: inputSchema(op), OutputSchema: json.RawMessage(`{"type":"object","additionalProperties":true}`)}, func(ctx context.Context, _ *mcp.CallToolRequest, args input) (*mcp.CallToolResult, json.RawMessage, error) {
				q := protocol.Request{Op: op.Name, App: args.App, Release: args.Release}
				if q.Validate() != nil || !allowed(grants, q.App, q.Op) {
					return nil, nil, protocol.ErrNotPermitted
				}
				data, err := forward(ctx, q)
				return nil, data, err
			})
		}
		if apps := overviewApps(grants); len(apps) > 0 {
			schema := json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
			mcp.AddTool(server, &mcp.Tool{Name: "overview", Description: "deployment_status and health of every authorized application", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}, InputSchema: schema, OutputSchema: json.RawMessage(`{"type":"object","additionalProperties":true}`)}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, json.RawMessage, error) {
				data, err := json.Marshal(overview(ctx, forward, grants, apps))
				return nil, data, err
			})
		}
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 8192}).ServeHTTP(w, r)
	}))
}

func inputSchema(op protocol.Op) json.RawMessage {
	name, _ := json.Marshal(map[string]string{"type": "string", "pattern": protocol.NamePattern})
	required := `["app"]`
	properties := `"app":` + string(name)
	if op.TakesRelease {
		required = `["app","release"]`
		properties += `,"release":` + string(name)
	}
	return json.RawMessage(`{"type":"object","properties":{` + properties + `},"required":` + required + `,"additionalProperties":false}`)
}

func overviewApps(grants []grant) []string {
	var apps []string
	for _, g := range grants {
		if !slices.Contains(g.Ops, protocol.DeploymentStatus) {
			continue
		}
		for _, app := range g.Apps {
			if !slices.Contains(apps, app) {
				apps = append(apps, app)
			}
		}
	}
	return apps
}

type overviewRow struct {
	App        string          `json:"app"`
	Deployment json.RawMessage `json:"deployment"`
	Health     json.RawMessage `json:"health"`
	Error      *string         `json:"error"`
}

// overview reads every app independently, so one unavailable app cannot hide the others.
func overview(ctx context.Context, forward forwardFunc, grants []grant, apps []string) map[string][]overviewRow {
	ctx, cancel := context.WithTimeout(ctx, overviewTimeout)
	defer cancel()
	rows := make([]overviewRow, len(apps))
	failed := make([][2]bool, len(apps))
	slots := make(chan struct{}, overviewParallel)
	var wg sync.WaitGroup
	read := func(op, app string, dst *json.RawMessage, failure *bool) {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			data, err := forward(ctx, protocol.Request{Op: op, App: app})
			if err != nil {
				*failure = true
				return
			}
			*dst = data
		})
	}
	for i, app := range apps {
		rows[i].App = app
		read(protocol.DeploymentStatus, app, &rows[i].Deployment, &failed[i][0])
		if allowed(grants, app, protocol.Health) {
			read(protocol.Health, app, &rows[i].Health, &failed[i][1])
		}
	}
	wg.Wait()
	for i := range rows {
		var problems []string
		if failed[i][0] {
			problems = append(problems, "deployment status unavailable")
		}
		if failed[i][1] {
			problems = append(problems, "health unavailable")
		}
		if len(problems) > 0 {
			message := strings.Join(problems, "; ")
			rows[i].Error = &message
		}
	}
	return map[string][]overviewRow{"apps": rows}
}

// errUnknown replaces every helper failure: helper errors may carry private detail.
var errUnknown = errors.New("operation result unavailable; inspect deployment status before retrying")

func helper(path string) forwardFunc {
	return func(ctx context.Context, req protocol.Request) (json.RawMessage, error) {
		ctx, cancel := context.WithTimeout(ctx, helperTimeout)
		defer cancel()
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		if err != nil {
			return nil, errUnknown
		}
		defer c.Close()
		if !rootPeer(c) {
			return nil, errUnknown
		}
		deadline, _ := ctx.Deadline()
		if c.SetDeadline(deadline) != nil {
			return nil, errUnknown
		}
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		if protocol.WriteRequest(c, req) != nil {
			return nil, errUnknown
		}
		return readResponse(c)
	}
}

func readResponse(r io.Reader) (json.RawMessage, error) {
	response, err := protocol.ReadResponse(r)
	if err != nil || !response.OK || response.Error != "" || !json.Valid(response.Data) {
		return nil, errUnknown
	}
	return response.Data, nil
}

// Run accepts HTTP only from root-owned Tailscale Serve over a private Unix socket.
func Run(ctx context.Context, httpSocket, helperSocket string) error {
	if !peerCredentialsSupported() {
		return errors.New("MCP requires Linux SO_PEERCRED")
	}
	if os.Geteuid() == 0 {
		return errors.New("MCP must run as an unprivileged user")
	}
	if !filepath.IsAbs(httpSocket) || !filepath.IsAbs(helperSocket) {
		return errors.New("absolute Unix socket paths required")
	}
	listener, err := net.Listen("unix", httpSocket)
	if err != nil {
		return fmt.Errorf("listen on private MCP socket: %w", err)
	}
	defer listener.Close()
	if err = os.Chmod(httpSocket, 0600); err != nil {
		return err
	}
	server := &http.Server{Handler: endpoint(helper(helperSocket)), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: helperTimeout + 5*time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, peerKey{}, rootPeer(c))
	}}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
