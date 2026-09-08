package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/materialize"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/telemetry"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	// This process holds key material, so a panic must not print goroutine
	// stacks: Go renders frame arguments as raw machine words and an init
	// system retains whatever a crashing service wrote. Only GOTRACEBACK can
	// turn that off, and only from outside, so the process checks and says so.
	telemetry.WarnIfCrashDumpsEnabled(os.Stderr)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-materializer:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	descriptorPath := flag.String("descriptor", "", "signed batch descriptor")
	cachePath := flag.String("cache", "", "raw ciphertext cache directory")
	partialsPath := flag.String("partials", "", "verified operator partial-decryption directory")
	outputPath := flag.String("out", "", "browser-readable verified object directory")
	interval := flag.Duration("interval", time.Second, "fixed local materialization scan interval")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath, "--descriptor": *descriptorPath,
		"--cache": *cachePath, "--partials": *partialsPath, "--out": *outputPath,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	network, err := topology.Load(*topologyPath, authority, time.Now().UTC())
	if err != nil {
		return err
	}
	descriptor, err := batch.LoadDescriptor(*descriptorPath, authority, network)
	if err != nil {
		return err
	}
	cache, err := rawcache.Open(*cachePath, 64)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*partialsPath, 0o700); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	worker := materialize.Materializer{
		Cache: cache, Descriptor: descriptor, PartialsDir: *partialsPath,
		OutputDir: *outputPath, Interval: *interval,
	}
	if err := worker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
