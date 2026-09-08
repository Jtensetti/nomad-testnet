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

	"github.com/Jtensetti/nomad-testnet/live/fetchplan"
	"github.com/Jtensetti/nomad-testnet/live/partialfetch"
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
		fmt.Fprintln(os.Stderr, "nomad-partial-fetch:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	planPath := flag.String("plan", "", "signed public partial-fetch plan")
	outputPath := flag.String("out", "", "local opaque partial-proof cache")
	interval := flag.Duration("interval", time.Second, "public fixed fetch interval")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath,
		"--plan": *planPath, "--out": *outputPath,
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
	plan, err := fetchplan.Load(*planPath, authority, network)
	if err != nil {
		return err
	}
	fetcher, err := partialfetch.New(network, plan.StreamID, *outputPath, *interval)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := fetcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
