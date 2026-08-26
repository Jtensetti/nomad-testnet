package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/bundle"
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
	//
	// Not for --check-health, which reads a status file, holds nothing, and
	// exits. Warning there puts the line into every healthcheck's output on
	// every interval, where it is noise that trains an operator to ignore the
	// warning that matters. An incident drill found it doing exactly that.
	if !isHealthCheck() {
		telemetry.WarnIfCrashDumpsEnabled(os.Stderr)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-node:", err)
		os.Exit(1)
	}
}

// checkNodeIsEmitting is the liveness gate for a supervisor.
//
// A node no longer stops when a local condition breaks its emission path: a
// full disk or an exhausted socket buffer costs the cell it interrupted and
// the schedule carries on. That is the right behaviour on the wire and it
// removes the crudest alarm an operator had, which was the process exiting.
// Checking that the process is up, or that its health file exists, no longer
// distinguishes a working node from one that has been silently dropping every
// cell for an hour. This reads what the node actually did.
// isHealthCheck reports whether this invocation is the liveness gate rather
// than a node. It reads the raw arguments because flag parsing happens inside
// run, after the warning would already have been printed.
func isHealthCheck() bool {
	for _, argument := range os.Args[1:] {
		if argument == "--check-health" || argument == "-check-health" ||
			strings.HasPrefix(argument, "--check-health=") ||
			strings.HasPrefix(argument, "-check-health=") {
			return true
		}
	}
	return false
}

func checkNodeIsEmitting(path string, maxSilence time.Duration, now time.Time) error {
	if maxSilence <= 0 {
		return errors.New("--max-silence must be positive")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read health file: %w", err)
	}
	var stats node.Stats
	if err := json.Unmarshal(encoded, &stats); err != nil {
		return fmt.Errorf("parse health file: %w", err)
	}
	if stats.UpdatedAt.IsZero() {
		return errors.New("health file carries no update time")
	}
	if stale := now.Sub(stats.UpdatedAt); stale > maxSilence {
		return fmt.Errorf("health file is %s old: the node stopped reporting", stale.Truncate(time.Millisecond))
	}
	if stats.LastSentAt.IsZero() {
		return fmt.Errorf("the node has emitted nothing since it started, %s ago; "+
			"%d emissions were dropped locally",
			now.Sub(stats.StartedAt).Truncate(time.Millisecond), stats.SendDropped)
	}
	if silent := now.Sub(stats.LastSentAt); silent > maxSilence {
		return fmt.Errorf("the node last emitted %s ago, beyond the %s limit; "+
			"%d emissions have been dropped locally",
			silent.Truncate(time.Millisecond), maxSilence, stats.SendDropped)
	}
	return nil
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	secretsPath := flag.String("secrets", "", "operator secret JSON")
	listen := flag.String("listen", "", "local UDP listen address")
	cachePath := flag.String("cache", "", "raw ciphertext cache directory")
	statePath := flag.String("state", "", "persistent sequence state file")
	healthPath := flag.String("health", "", "local health JSON path")
	seedPath := flag.String("seed", "", "optional public encrypted seed bundle")
	cacheStreams := flag.Int("cache-streams", 64, "maximum immutable raw-cache streams")
	cacheSweep := flag.Duration("cache-sweep", 30*time.Second, "public cache replication sweep")
	checkHealth := flag.String("check-health", "", "read a health file and exit non-zero if the node is not emitting")
	maxSilence := flag.Duration("max-silence", 30*time.Second, "how long a node may emit nothing before --check-health fails")
	flag.Parse()
	if *checkHealth != "" {
		return checkNodeIsEmitting(*checkHealth, *maxSilence, time.Now().UTC())
	}
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath, "--secrets": *secretsPath,
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
	// A valid signature and an unexpired window do not make a topology
	// current: an older one inside its own window verifies just as well, and
	// replaying it is how a removed operator or a rotated-away key is put
	// back without forging anything. Refuse to move backwards, and fail
	// closed on two topologies signed for the same network epoch.
	watermarkPath := filepath.Join(filepath.Dir(*statePath), "topology-watermark.json")
	if err := topology.AcceptMonotonic(watermarkPath, verifiedTopology); err != nil {
		return err
	}
	secrets, err := topology.LoadSecrets(*secretsPath, verifiedTopology)
	if err != nil {
		return err
	}
	// The cache is shared between every operator that may send to this node
	// and this node itself, so it is opened with a per-sender share. Without
	// one, the first operator to fill it stops every other operator's work
	// from being admitted at all -- bounded memory, unbounded unfairness.
	self := verifiedTopology.Document.Operators[secrets.Operator.Index]
	senders := []uint16{self.Index}
	for _, peer := range verifiedTopology.IncomingPeers(self.Index) {
		senders = append(senders, peer.Index)
	}
	cache, err := rawcache.OpenShared(*cachePath, *cacheStreams, senders)
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
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := liveNode.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
