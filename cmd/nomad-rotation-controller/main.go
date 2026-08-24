package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/rotation"
	"github.com/Jtensetti/nomad-testnet/live/telemetry"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	telemetry.WarnIfCrashDumpsEnabled(os.Stderr)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-rotation-controller:", err)
		os.Exit(1)
	}
}

func run() error {
	chainPath := flag.String("chain", "", "persisted verified epoch-chain directory")
	revocationPath := flag.String("revocations", "", "persisted accepted-revocation directory")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	networkID := flag.String("network", "", "network identifier")
	operatorID := flag.String("operator-id", "", "local operator identifier")
	topologyDir := flag.String("topology-dir", "", "public retry topology root; epoch-N/attempt-NN/topology.json")
	secretsRoot := flag.String("secrets-dir", "", "private epoch-secret directory; epoch-NNN.secrets.json")
	listen := flag.String("listen", "", "local DKG HTTP(S) listen address")
	stateRoot := flag.String("state", "", "rotation/DKG state root")
	shareRoot := flag.String("share-dir", "", "private successor-share output directory")
	certRoot := flag.String("certificate-dir", "", "public successor-certificate output directory")
	exchangeRoot := flag.String("exchange", "", "public immutable epoch-artifact directory")
	journalRoot := flag.String("signature-journal", "", "private descriptor anti-equivocation journal directory")
	controlListen := flag.String("control-listen", "", "lifecycle control listen address; signed DKG endpoint port plus one")
	tlsCertificate := flag.String("tls-certificate", "", "TLS certificate for an HTTPS DKG endpoint")
	tlsPrivateKey := flag.String("tls-private-key", "", "TLS private key for an HTTPS DKG endpoint")
	prepareLead := flag.Duration("prepare-lead", 6*time.Hour, "public successor preparation lead")
	retryOffsets := flag.String("retry-offsets", "1h,2h", "comma-separated public retry offsets")
	escalateAfter := flag.Duration("escalate-after", 3*time.Hour, "public escalation offset")
	controlInterval := flag.Duration("control-interval", 30*time.Second, "public aligned interval while awaiting control-plane artifacts")
	once := flag.Bool("once", false, "perform one lifecycle step and exit")
	flag.Parse()
	if flag.NArg() != 0 || *chainPath == "" || *authorityPath == "" || *networkID == "" || *operatorID == "" ||
		*revocationPath == "" || *topologyDir == "" || *secretsRoot == "" || *listen == "" || *stateRoot == "" || *shareRoot == "" || *certRoot == "" ||
		*exchangeRoot == "" || *journalRoot == "" || *controlListen == "" {
		return errors.New("--chain, --revocations, --authority-key, --network, --operator-id, --topology-dir, --secrets-dir, --listen, --state, --share-dir, --certificate-dir, --exchange, --signature-journal and --control-listen are required")
	}
	if *controlInterval < time.Second || *controlInterval > 10*time.Minute {
		return errors.New("--control-interval must be between one second and ten minutes")
	}
	if err := validateControlBinding(*listen, *controlListen); err != nil {
		return err
	}
	if (*tlsCertificate == "") != (*tlsPrivateKey == "") {
		return errors.New("TLS requires both --tls-certificate and --tls-private-key")
	}
	if *tlsCertificate != "" {
		if _, err := tls.LoadX509KeyPair(*tlsCertificate, *tlsPrivateKey); err != nil {
			return fmt.Errorf("load lifecycle TLS identity: %w", err)
		}
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
		TopologyDir: *topologyDir, SecretsRoot: *secretsRoot, Listen: *listen,
		StateRoot: *stateRoot, ShareRoot: *shareRoot, CertRoot: *certRoot,
		TLSCert: *tlsCertificate, TLSKey: *tlsPrivateKey,
	}
	coordinator, err := rotation.NewCoordinator(rotation.CoordinatorConfig{
		Controller: controller, ChainRoot: *chainPath, RevocationRoot: *revocationPath,
		ExchangeRoot: *exchangeRoot, JournalRoot: *journalRoot,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", *controlListen)
	if err != nil {
		return fmt.Errorf("listen for epoch control: %w", err)
	}
	server := &http.Server{
		Handler: coordinator.Handler(), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() {
		var serveErr error
		if *tlsCertificate != "" || *tlsPrivateKey != "" {
			if *tlsCertificate == "" || *tlsPrivateKey == "" {
				serveErr = errors.New("control TLS requires both certificate and private key")
			} else {
				serveErr = server.ServeTLS(listener, *tlsCertificate, *tlsPrivateKey)
			}
		} else {
			serveErr = server.Serve(listener)
		}
		if !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
			stop()
		}
	}()
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	encoder := json.NewEncoder(os.Stdout)
	for {
		now := time.Now().UTC()
		outcome, err := controller.Step(ctx, now)
		if err != nil {
			select {
			case serverErr := <-serverErrors:
				return fmt.Errorf("epoch control server: %w", serverErr)
			default:
			}
			return err
		}
		if outcome.Status == rotation.StatusDKGComplete || outcome.Status == rotation.StatusNotParticipant {
			// DKG may have waited through several phases. Re-read the public
			// clock so a stale pre-DKG timestamp can never authorize late
			// descriptor signing or catch-up activation.
			coordinationNow := time.Now().UTC()
			coordinated, err := coordinator.Advance(ctx, coordinationNow, outcome.Epoch, outcome.Attempt)
			if err != nil {
				return err
			}
			outcome.Coordination = &coordinated
		}
		if err := encoder.Encode(outcome); err != nil {
			return err
		}
		if *once {
			return nil
		}
		// Processing can cross one or more grid ticks. Always schedule from a
		// fresh clock reading; scheduling from the loop's old timestamp would
		// generate an immediate burst of catch-up control requests.
		wake := nextWake(time.Now().UTC(), outcome, *controlInterval)
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

func validateControlBinding(dkgListen, controlListen string) error {
	_, dkgPortText, err := net.SplitHostPort(dkgListen)
	if err != nil {
		return fmt.Errorf("invalid DKG listen address: %w", err)
	}
	_, controlPortText, err := net.SplitHostPort(controlListen)
	if err != nil {
		return fmt.Errorf("invalid lifecycle control listen address: %w", err)
	}
	dkgPort, dkgErr := strconv.Atoi(dkgPortText)
	controlPort, controlErr := strconv.Atoi(controlPortText)
	if dkgErr != nil || controlErr != nil || dkgPort < 1 || dkgPort >= 65535 || controlPort != dkgPort+1 {
		return errors.New("lifecycle control listen port must be the DKG listen port plus one")
	}
	return nil
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
