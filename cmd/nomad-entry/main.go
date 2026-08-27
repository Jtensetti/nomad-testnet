// Command nomad-entry is the entry operator service.
//
// It terminates publisher uplinks and fills the deposit mailbox. Until this
// existed the role had no process at all: the responder and the airlock were
// both exercised, and nothing ran them together, so everything known about what
// an entry operator can observe was known from inside a single test binary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/entry"
	"github.com/Jtensetti/nomad-testnet/live/telemetry"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	// This process holds key material, so a panic must not print goroutine
	// stacks: Go renders frame arguments as raw machine words and an init
	// system retains whatever a crashing service wrote.
	telemetry.WarnIfCrashDumpsEnabled(os.Stderr)
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-entry:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("nomad-entry", flag.ContinueOnError)
	topologyPath := flags.String("topology", "", "signed public topology JSON")
	authorityPath := flags.String("authority-key", "", "pinned topology authority public key")
	secretsPath := flags.String("secrets", "", "operator secret JSON")
	certificatePath := flags.String("dkg-certificate", "",
		"all-operator-certified distributed DKG certificate")
	listen := flags.String("listen", "", "local UDP listen address for publisher uplinks")
	batches := flags.String("batches", "", "directory sealed batches are written to")
	healthPath := flags.String("health", "", "local health JSON path")
	sessions := flags.Int("sessions", 256, "maximum concurrent uplink sessions")
	batchSize := flags.Int("batch-size", 64, "fixed slots per release epoch, real and cover")
	period := flags.Duration("period", time.Minute, "length of one release epoch")
	cutoff := flags.Duration("deposit-cutoff", 15*time.Second,
		"how long before release the deposit window closes")
	perSession := flags.Int("per-session", 8, "maximum deposits one session may hold in an epoch")
	checkHealth := flags.String("check-health", "",
		"read a health file and exit non-zero if the service is not sealing")
	maxSilence := flags.Duration("max-silence", 5*time.Minute,
		"how long a service may seal nothing before --check-health fails")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	if *checkHealth != "" {
		return checkHealthFile(*checkHealth, *maxSilence, time.Now().UTC())
	}

	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath,
		"--secrets": *secretsPath, "--dkg-certificate": *certificatePath,
		"--listen": *listen, "--batches": *batches,
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
	// LoadSecrets is called for its binding check -- it refuses a secrets file
	// whose key-agreement public half is not the one this operator published in
	// the signed topology -- and LoadPrivateKeys for the key itself, which the
	// verified form does not carry because the relay path has no use for it.
	if _, err := topology.LoadSecrets(*secretsPath, network); err != nil {
		return err
	}
	private, err := topology.LoadPrivateKeys(*secretsPath)
	if err != nil {
		return err
	}
	certificateBytes, err := readBounded(*certificatePath, committee.MaximumFileBytes)
	if err != nil {
		return err
	}
	_, certified, err := committee.Decode(certificateBytes, network)
	if err != nil {
		return fmt.Errorf("DKG certificate: %w", err)
	}

	schedule, err := releaseSchedule(network, *period, *cutoff, *batchSize, *perSession)
	if err != nil {
		return err
	}

	service, err := entry.New(entry.Config{
		Topology:       network,
		KEX:            private.KEX,
		Committee:      certified.Committee,
		ListenAddress:  *listen,
		BatchDirectory: *batches,
		HealthPath:     *healthPath,
		Schedule:       schedule,
		SessionLimit:   *sessions,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return service.Run(ctx)
}

// releaseSchedule anchors the release epochs to the signed topology's validity
// start.
//
// Anchoring to the document rather than to a flag is the point: every operator
// in an epoch derives the same boundaries from the same signed bytes, so there
// is nothing for them to disagree about. A genesis each operator configured
// independently would be a deposit cutoff they could disagree about, and a
// disagreement about the cutoff is a split batch.
//
// The period, cutoff, batch size and per-session bound are still flags, and
// that is a gap rather than a design: they must be identical across operators
// for the same reason, and they belong in the signed document. Putting them
// there is a wire-format change to the topology and is recorded as open work.
func releaseSchedule(network topology.Verified, period, cutoff time.Duration,
	batchSize, perSession int) (airlock.Schedule, error) {
	genesis, err := time.Parse(time.RFC3339, network.Document.NotBefore)
	if err != nil {
		return airlock.Schedule{}, fmt.Errorf("topology not_before: %w", err)
	}
	schedule := airlock.Schedule{
		Genesis:               genesis.UTC(),
		Period:                period,
		DepositCutoff:         cutoff,
		BatchSize:             batchSize,
		MaxDepositsPerSession: perSession,
	}
	if err := schedule.Validate(); err != nil {
		return airlock.Schedule{}, err
	}
	return schedule, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a bounded regular file", path)
	}
	return os.ReadFile(path)
}

// checkHealthFile is the liveness probe. It fails closed on anything it cannot
// read or parse: a probe that passed on an unreadable file would report a
// healthy service for a machine whose disk had gone.
func checkHealthFile(path string, maxSilence time.Duration, now time.Time) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read health file: %w", err)
	}
	var stats entry.Stats
	if err := json.Unmarshal(encoded, &stats); err != nil {
		return fmt.Errorf("parse health file: %w", err)
	}
	if stats.UpdatedAt.IsZero() {
		return errors.New("health file carries no update time")
	}
	if stale := now.Sub(stats.UpdatedAt); stale > maxSilence {
		return fmt.Errorf("health file is %s old: the service stopped reporting",
			stale.Truncate(time.Millisecond))
	}
	// Sealing, not receiving, is the liveness signal. A service that receives
	// nothing may simply have no publishers; a service that seals nothing has a
	// mailbox that is not moving, and every deposit it has taken is stuck in it.
	if stats.LastSealedAt.IsZero() {
		return fmt.Errorf("the service has sealed nothing since it started, %s ago; "+
			"%d cells accepted", now.Sub(stats.StartedAt).Truncate(time.Millisecond),
			stats.Accepted)
	}
	if silent := now.Sub(stats.LastSealedAt); silent > maxSilence {
		return fmt.Errorf("the service last sealed %s ago, beyond the %s limit",
			silent.Truncate(time.Millisecond), maxSilence)
	}
	return nil
}
