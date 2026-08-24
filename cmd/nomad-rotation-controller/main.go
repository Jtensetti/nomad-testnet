package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/rotation"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-rotation-controller:", err)
		os.Exit(1)
	}
}

func run() error {
	chainPath := flag.String("chain", "", "persisted verified epoch-chain directory")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	networkID := flag.String("network", "", "network identifier")
	operatorID := flag.String("operator-id", "", "local operator identifier")
	topologyDir := flag.String("topology-dir", "", "public retry topology root; epoch-N/attempt-NN/topology.json")
	secretsPath := flag.String("secrets", "", "local operator secret path")
	listen := flag.String("listen", "", "local DKG HTTP(S) listen address")
	stateRoot := flag.String("state", "", "rotation/DKG state root")
	shareRoot := flag.String("share-dir", "", "private successor-share output directory")
	certRoot := flag.String("certificate-dir", "", "public successor-certificate output directory")
	tlsCertificate := flag.String("tls-certificate", "", "TLS certificate for an HTTPS DKG endpoint")
	tlsPrivateKey := flag.String("tls-private-key", "", "TLS private key for an HTTPS DKG endpoint")
	prepareLead := flag.Duration("prepare-lead", 6*time.Hour, "public successor preparation lead")
	retryOffsets := flag.String("retry-offsets", "1h,2h", "comma-separated public retry offsets")
	escalateAfter := flag.Duration("escalate-after", 3*time.Hour, "public escalation offset")
	controlInterval := flag.Duration("control-interval", 30*time.Second, "public aligned interval while awaiting control-plane artifacts")
	once := flag.Bool("once", false, "perform one lifecycle step and exit")
	flag.Parse()
	if flag.NArg() != 0 || *chainPath == "" || *authorityPath == "" || *networkID == "" || *operatorID == "" ||
		*topologyDir == "" || *secretsPath == "" || *listen == "" || *stateRoot == "" || *shareRoot == "" || *certRoot == "" {
		return errors.New("--chain, --authority-key, --network, --operator-id, --topology-dir, --secrets, --listen, --state, --share-dir and --certificate-dir are required")
	}
	if *controlInterval < time.Second {
		return errors.New("--control-interval must be at least one second")
	}
	offsets, err := parseDurations(*retryOffsets)
	if err != nil {
		return err
	}
	policy := epoch.Policy{PrepareLead: *prepareLead, RetryOffsets: offsets, EscalateAfter: *escalateAfter}

	// The process lock spans chain reads, retry decisions and the DKG itself.
	// Two controller instances must never overlap different retry attempts on
	// the same operator state root.
	processLock, err := rotation.AcquireProcessLock(*stateRoot)
	if err != nil {
		return err
	}
	defer func() { _ = processLock.Release() }()

	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*chainPath, *networkID, authority, nil)
	if err != nil {
		return err
	}
	controller := rotation.Config{
		Planner: chain, Policy: policy, OperatorID: *operatorID, Authority: authority, NetworkID: *networkID,
		TopologyDir: *topologyDir, SecretsPath: *secretsPath, Listen: *listen,
		StateRoot: *stateRoot, ShareRoot: *shareRoot, CertRoot: *certRoot,
		TLSCert: *tlsCertificate, TLSKey: *tlsPrivateKey,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(os.Stdout)
	for {
		now := time.Now().UTC()
		outcome, err := controller.Step(ctx, now)
		if err != nil {
			return err
		}
		if err := encoder.Encode(outcome); err != nil {
			return err
		}
		if *once {
			return nil
		}
		wake := nextWake(now, outcome, *controlInterval)
		timer := time.NewTimer(time.Until(wake))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

func nextWake(now time.Time, outcome rotation.Outcome, interval time.Duration) time.Time {
	if (outcome.Status == rotation.StatusIdle || outcome.Status == rotation.StatusAwaitActivation) && outcome.DueAt.After(now) {
		return outcome.DueAt
	}
	return nextAlignedTick(now, interval)
}

func nextAlignedTick(now time.Time, interval time.Duration) time.Time {
	nanos := now.UTC().UnixNano()
	step := interval.Nanoseconds()
	next := (nanos/step + 1) * step
	return time.Unix(0, next).UTC()
}

func parseDurations(encoded string) ([]time.Duration, error) {
	parts := strings.Split(encoded, ",")
	result := make([]time.Duration, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := time.ParseDuration(part)
		if err != nil {
			return nil, fmt.Errorf("invalid retry offset %q: %w", part, err)
		}
		result = append(result, value)
	}
	return result, nil
}
