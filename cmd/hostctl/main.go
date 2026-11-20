package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"minimal.host/platform/internal/engine"
	"minimal.host/platform/internal/protocol"
)

func main() {
	if err := mainRun(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func mainRun() error {
	if len(os.Args) < 2 {
		return errors.New("usage: hostctl helper|poll|reconcile|doctor APP|config-check FILE|update-release-policy FILE|resume APP AFTER_RUN_ID")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	command := os.Args[1]
	if command == "config-check" && len(os.Args) == 3 {
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			return err
		}
		c, h, err := engine.ReadConfig(b)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"app": c.App, "config_sha256": h})
	}
	if os.Geteuid() != 0 {
		return errors.New("administrator or socket-activated helper required")
	}
	m := engine.New()
	switch command {
	case "helper":
		if len(os.Args) != 2 {
			return errors.New("helper accepts no arguments")
		}
		ctx, stop := context.WithTimeout(ctx, engine.OperationTimeout)
		defer stop()
		q, err := protocol.ReadRequest(os.Stdin)
		var result any
		if err == nil {
			result, err = m.Handle(ctx, q)
		}
		return protocol.WriteResponse(os.Stdout, result, err)
	case "doctor":
		if len(os.Args) != 3 {
			return errors.New("doctor requires application")
		}
		health, err := m.Health(ctx, os.Args[2])
		if err != nil {
			return err
		}
		if err = json.NewEncoder(os.Stdout).Encode(health); err != nil {
			return err
		}
		if !health.Healthy {
			return errors.New("application health check failed")
		}
		return nil
	case "poll":
		if len(os.Args) != 2 {
			return errors.New("poll accepts no arguments")
		}
		recoveryErr := m.RecoverPending(ctx)
		token, err := os.ReadFile("/etc/minimal-host/secrets/github-token")
		if err != nil || len(token) == 0 || len(token) > 4096 {
			return errors.Join(recoveryErr, errors.New("GitHub read credential unavailable"))
		}
		return errors.Join(recoveryErr, m.Poll(ctx, engine.NewGitHub(string(bytes.TrimSpace(token)))))
	case "reconcile":
		if len(os.Args) != 2 {
			return errors.New("reconcile accepts no arguments")
		}
		return m.Reconcile(ctx)
	case "update-release-policy":
		if len(os.Args) != 3 {
			return errors.New("update-release-policy requires a reviewed manifest file")
		}
		return m.UpdateReleasePolicy(os.Args[2])
	case "resume":
		if len(os.Args) != 4 {
			return errors.New("resume requires application and explicit workflow-run barrier")
		}
		barrier, err := strconv.ParseInt(os.Args[3], 10, 64)
		if err != nil || barrier < 0 {
			return errors.New("invalid workflow-run barrier")
		}
		return m.Resume(os.Args[2], barrier)
	}
	return errors.New("unknown command")
}
