// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	authorizer "github.com/yyichenn/containerd-aws-rfc9421-authorizer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "containerd-aws-rfc9421-authorizer: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		socketPath = flag.String(
			"socket",
			"/run/containerd/aws-rfc9421-authorizer.sock",
			"Unix socket exposed to containerd",
		)
		region            = flag.String("region", "", "AWS signing region")
		credentialContext = flag.String(
			"credential-context",
			"",
			"optional opaque handle required from containerd",
		)
	)
	flag.Parse()
	if *region == "" {
		return errors.New("--region is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	signer, err := authorizer.NewDefaultSigner(ctx, *region)
	if err != nil {
		return fmt.Errorf("create AWS credential signer: %w", err)
	}
	var handlerOptions []authorizer.HandlerOption
	if *credentialContext != "" {
		handlerOptions = append(
			handlerOptions,
			authorizer.WithCredentialContext([]byte(*credentialContext)),
		)
	}
	handler, err := authorizer.NewHandler(signer, handlerOptions...)
	if err != nil {
		return fmt.Errorf("create authorizer handler: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o750); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", *socketPath, err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(*socketPath)
	}()
	if err := os.Chmod(*socketPath, 0o600); err != nil {
		return fmt.Errorf("protect authorizer socket: %w", err)
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()

	fmt.Printf("AWS RFC 9421 authorizer listening on %s\n", *socketPath)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve authorizer requests: %w", err)
	}
	return nil
}
