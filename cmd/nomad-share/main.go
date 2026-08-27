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
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/share"
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
		fmt.Fprintln(os.Stderr, "nomad-share:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	epochChainPath := flag.String("epoch-chain", "", "persisted verified epoch-chain directory")
	descriptorPath := flag.String("descriptor", "", "signed batch descriptor")
	sharePath := flag.String("share", "", "operator threshold share")
	cachePath := flag.String("cache", "", "operator raw cache")
	outputPath := flag.String("out", "", "public partial-decryption directory")
	listen := flag.String("listen", "", "public partial-proof HTTP listen address")
	interval := flag.Duration("interval", time.Second, "fixed local cache scan interval")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath, "--epoch-chain": *epochChainPath,
		"--descriptor": *descriptorPath, "--share": *sharePath, "--cache": *cachePath,
		"--out": *outputPath, "--listen": *listen,
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
	chain, err := epoch.OpenChain(*epochChainPath, network.Document.NetworkID, authority, nil)
	if err != nil {
		return fmt.Errorf("open epoch chain: %w", err)
	}
	current, exists, err := chain.FreshEpoch(network.Document.Epoch)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("epoch %d is not present in the local verified chain; import it with nomad-lifecycle first", network.Document.Epoch)
	}
	if current.Topology.Digest != network.Digest {
		return errors.New("epoch chain does not authorize the configured topology")
	}
	guard := epoch.FreshGuard{Chain: chain}
	if err := guard.ServesEpoch(network.Document.Epoch, time.Now().UTC()); err != nil {
		return fmt.Errorf("epoch chain does not authorize threshold service: %w", err)
	}
	descriptor, err := batch.LoadDescriptor(*descriptorPath, authority, network)
	if err != nil {
		return err
	}
	secret, err := batch.LoadShare(*sharePath, descriptor, network)
	if err != nil {
		return err
	}
	cache, err := rawcache.Open(*cachePath, 64)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service := share.Service{
		Cache: cache, Descriptor: descriptor, Secret: secret, OutputDir: *outputPath,
		Interval: *interval, ListenAddress: *listen, Guard: guard,
	}
	if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
