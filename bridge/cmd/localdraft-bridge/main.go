package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"localdraftai/bridge/internal/appserver"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("localdraft-bridge: %v", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "serve" {
		return errors.New("usage: localdraft-bridge serve [options]")
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listenAddress := flags.String("listen", appserver.DefaultListenAddress, "listen address")
	publicOrigin := flags.String("public-origin", "", "canonical HTTPS bridge origin")
	tlsCert := flags.String("tls-cert", "", "TLS certificate chain file")
	tlsKey := flags.String("tls-key", "", "TLS private key file")
	webRoot := flags.String("web-root", ".", "LocalDraftAI repository web root")
	configDir := flags.String("config-dir", "", "bridge configuration directory")
	logLevel := flags.String("log-level", "info", "bridge log level")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *logLevel != "debug" && *logLevel != "info" && *logLevel != "warn" && *logLevel != "error" {
		return errors.New("log level must be debug, info, warn, or error")
	}
	if err := appserver.ValidateListenAddress(*listenAddress); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	server, err := appserver.New(appserver.Config{
		ListenAddress: listener.Addr().String(),
		PublicOrigin:  *publicOrigin,
		TLSCertFile:   *tlsCert,
		TLSKeyFile:    *tlsKey,
		WebRoot:       *webRoot,
		ConfigDir:     *configDir,
	})
	if err != nil {
		return err
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	log.Printf("LocalDraft Bridge %s listening at %s", appserver.BridgeVersion, server.Origin())
	if err := writeStartupURL(os.Stdout, server.StartupURL()); err != nil {
		return fmt.Errorf("print startup URL: %w", err)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-errCh:
		return err
	case <-signals:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	}
}

func writeStartupURL(writer io.Writer, startupURL string) error {
	_, err := fmt.Fprintln(writer, startupURL)
	return err
}
