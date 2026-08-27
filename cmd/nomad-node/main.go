package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/bundle"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/node"
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
		fmt.Fprintln(os.Stderr, "nomad-node:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	epochChainPath := flag.String("epoch-chain", "", "persisted verified epoch-chain directory")
	secretsPath := flag.String("secrets", "", "operator secret JSON")
	listen := flag.String("listen", "", "local UDP listen address")
	cachePath := flag.String("cache", "", "raw ciphertext cache directory")
	statePath := flag.String("state", "", "persistent sequence state file")
	healthPath := flag.String("health", "", "local health JSON path")
	seedPath := flag.String("seed", "", "optional public encrypted seed bundle")
	cacheStreams := flag.Int("cache-streams", 64, "maximum immutable raw-cache streams")
	cacheSweep := flag.Duration("cache-sweep", 30*time.Second, "public cache replication sweep")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath, "--epoch-chain": *epochChainPath, "--secrets": *secretsPath,
		"--listen": *listen, "--cache": *cachePath, "--state": *statePath, "--health": *healthPath,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	verifiedTopology, err := topology.Load(*topologyPath, authority, time.Now().UTC())
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*epochChainPath, verifiedTopology.Document.NetworkID, authority, nil)
	if err != nil {
		return fmt.Errorf("open epoch chain: %w", err)
	}
	current, exists, err := chain.FreshEpoch(verifiedTopology.Document.Epoch)
	if err != nil {
		return err
	}
	if !exists || current.Topology.Digest != verifiedTopology.Digest {
		return errors.New("epoch chain does not authorize the configured topology")
	}
	// Only a fully approved descriptor may advance the node watermark. Doing
	// this before the chain comparison would let an authority-signed but
	// unapproved topology burn a slot and deny the real membership transition.
	watermarkPath := filepath.Join(filepath.Dir(*statePath), "topology-watermark.json")
	if err := topology.AcceptMonotonic(watermarkPath, verifiedTopology); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Starting a service before the signed public activation instant is a
	// normal operational condition, not a crash. Wait locally and emit no
	// network work until the descriptor says the epoch is eligible. The
	// FreshGuard below re-reads the chain at the boundary, so a halt or other
	// verified lifecycle change still fails closed before any socket opens.
	if err := waitUntilPublicActivation(ctx, current.ActivateAt); err != nil {
		return err
	}
	guard := epoch.FreshGuard{Chain: chain}
	if err := guard.ServesEpoch(current.Epoch, time.Now().UTC()); err != nil {
		return fmt.Errorf("epoch chain does not authorize network service: %w", err)
	}
	servingDeadline, err := chain.FreshServingDeadline(current.Epoch)
	if err != nil {
		return err
	}
	var deadlineNanos atomic.Int64
	deadlineNanos.Store(servingDeadline.UnixNano())
	secrets, err := topology.LoadSecrets(*secretsPath, verifiedTopology)
	if err != nil {
		return err
	}
	cache, err := rawcache.Open(*cachePath, *cacheStreams)
	if err != nil {
		return err
	}
	var seed *bundle.Verified
	if *seedPath != "" {
		loaded, err := bundle.Load(*seedPath)
		if err != nil {
			return err
		}
		seed = &loaded
	}
	liveNode, err := node.New(node.Config{
		Topology: verifiedTopology, Secrets: secrets, ListenAddress: *listen,
		Cache: cache, SequencePath: *statePath, HealthPath: *healthPath,
		CacheSweep: *cacheSweep, Seed: seed,
		ServingDeadline: func() time.Time {
			return time.Unix(0, deadlineNanos.Load()).UTC()
		},
	})
	if err != nil {
		return err
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- watchServingDeadline(runContext, cancel, chain, current.Epoch, &deadlineNanos)
	}()
	runErr := liveNode.Run(runContext)
	cancel()
	watchErr := <-watchDone
	if watchErr != nil {
		return watchErr
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, node.ErrEpochInactive) {
		return runErr
	}
	return nil
}

// waitUntilPublicActivation is deliberately local-only. It opens no socket,
// reads no private state and cannot accelerate the signed public boundary.
func waitUntilPublicActivation(ctx context.Context, activateAt time.Time) error {
	if ctx == nil {
		return errors.New("activation wait context is required")
	}
	wait := time.Until(activateAt)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// watchServingDeadline refreshes the public epoch chain on a fixed one-second
// grid. It may only shorten the hot-path deadline when a verified emergency
// successor appears. Neither cache contents nor user activity are inputs.
func watchServingDeadline(ctx context.Context, cancel context.CancelFunc, chain *epoch.Chain, epochNumber uint64, deadlineNanos *atomic.Int64) error {
	if ctx == nil || cancel == nil || chain == nil || deadlineNanos == nil {
		return errors.New("complete epoch serving watcher configuration is required")
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		deadline := time.Unix(0, deadlineNanos.Load()).UTC()
		wait := time.Until(deadline)
		if wait <= 0 {
			cancel()
			return nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
			cancel()
			return nil
		case <-ticker.C:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			fresh, err := chain.FreshServingDeadline(epochNumber)
			if err != nil {
				cancel()
				return fmt.Errorf("refresh epoch serving deadline: %w", err)
			}
			if fresh.Before(deadline) {
				deadlineNanos.Store(fresh.UnixNano())
			}
		}
	}
}
