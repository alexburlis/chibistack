package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

//go:embed site/index.html
var index string

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ready")
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, index)
	})
	return mux
}

// selfTest uses the production handler without opening sockets or writing files.
func selfTest() error {
	h := handler()
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/ready", 200, "ready\n"},
		{"GET", "/", 200, index},
		{"HEAD", "/ready", 200, ""},
		{"GET", "/missing", 404, ""},
		{"POST", "/ready", 405, ""},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.status || (tc.body != "" && rec.Body.String() != tc.body) {
			return fmt.Errorf("%s %s: unexpected response", tc.method, tc.path)
		}
	}
	return nil
}

func run() error {
	if filepath.Base(os.Args[0]) == "test" || (len(os.Args) == 2 && os.Args[1] == "--self-test") {
		if err := selfTest(); err != nil {
			return err
		}
		fmt.Println("HTTP handler checks passed")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{
		Addr:              ":8080",
		Handler:           handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("HTTP shutdown: %v", err)
			server.Close()
		}
	}()
	log.Print("HTTP example listening on :8080")
	err := server.ListenAndServe()
	stop()
	<-stopped
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
