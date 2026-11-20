package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"minimal.host/platform/internal/mcpgate"
)

func main() {
	socket := flag.String("socket", "", "absolute Unix HTTP socket path")
	helper := flag.String("helper", "", "absolute root helper socket path")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected MCP arguments")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := mcpgate.Run(ctx, *socket, *helper); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
