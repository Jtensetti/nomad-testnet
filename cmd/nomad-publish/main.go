// Command nomad-publish is the publisher half of the publication airlock: it
// puts an object into a local queue, and emits that queue to an entry operator
// at a fixed cadence.
//
// It exists because the airlock had no production caller. The uplink session,
// the deposit drain and the bounded queue were all implemented and tested, and
// the only non-test code that constructed any of them was the conformance
// vector generator -- so PROD-17 and PROD-18 both carried "the publication
// uplink is not on a production path" as a blocker, and both were right.
//
// Building it found what that costs. The uplink sequence is the AEAD nonce,
// nothing persisted it, and every caller was an in-process test that counted
// from one and never restarted. A publisher built without noticing would have
// re-sealed fragments under nonces it had already used on every restart. See
// live/uplink/sequence.go.
//
// What this command does NOT do, stated here because a reader will look for
// it: it does not establish the uplink session in band. The shared secret is
// read from a file both parties already have. Nothing in the cell format
// carries a publisher's ephemeral key -- the 1200 bytes are spent on the
// sequence, the committee ciphertext and the tag, leaving 24 bytes of padding
// -- so an in-band handshake is a wire-format change and not something to
// invent quietly. See nomad-protocol production/DECISIONS.md DEC-015.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/deposit"
	"github.com/Jtensetti/nomad-testnet/live/publish"
	"github.com/Jtensetti/nomad-testnet/live/telemetry"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

func main() {
	telemetry.WarnIfCrashDumpsEnabled(os.Stderr)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-publish:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	queuePath := flag.String("queue", "", "local publication queue directory")
	statePath := flag.String("state", "", "durable uplink sequence state file")
	secretPath := flag.String("session-secret", "", "file holding the pre-shared uplink secret")
	committeePath := flag.String("committee-key", "", "file holding the epoch committee public key")
	entry := flag.String("entry", "", "entry operator ID from the signed topology")
	submit := flag.String("submit", "", "submit this file to the local queue and exit")
	publisherPath := flag.String("publisher-key", "", "file holding the site's ed25519 public "+
		"key, in base64, that this object is published under")
	maxFragments := flag.Int("queue-fragments", 4096, "bound on the local queue")
	flag.Parse()

	if *queuePath == "" {
		return errors.New("--queue is required")
	}
	queue, err := publish.Open(*queuePath, publish.Options{MaximumFragments: *maxFragments})
	if err != nil {
		return err
	}

	// Submitting touches no network at all, and the flag set is checked
	// separately so that a publisher can queue an object on a machine that
	// has no uplink configured.
	if *submit != "" {
		if *publisherPath == "" {
			return errors.New("--publisher-key is required to submit: a publication is " +
				"bound to a site identity, and the queue refuses a fragment that names none")
		}
		return submitObject(queue, *submit, *publisherPath)
	}

	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath,
		"--state": *statePath, "--session-secret": *secretPath,
		"--committee-key": *committeePath, "--entry": *entry,
	} {
		if value == "" {
			return fmt.Errorf("%s is required to emit", name)
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
	operator, err := entryOperator(network, *entry)
	if err != nil {
		return err
	}
	committee, err := loadCommitteeKey(*committeePath)
	if err != nil {
		return err
	}
	secret, err := loadSessionSecret(*secretPath)
	if err != nil {
		return err
	}

	session, err := uplink.NewSession(secret, committee, uplink.Context{
		NetworkID:      network.Document.NetworkID,
		Epoch:          network.Document.Epoch,
		TopologyDigest: network.Digest,
		EntryOperator:  operator.Index,
	})
	if err != nil {
		return err
	}
	sequence, err := uplink.OpenFileSequence(*statePath)
	if err != nil {
		return err
	}
	drain, err := deposit.NewDrain(session, queue)
	if err != nil {
		return err
	}
	defer drain.Close()

	target, err := net.ResolveUDPAddr("udp", operator.Endpoint)
	if err != nil {
		return fmt.Errorf("resolve entry operator %s: %w", operator.ID, err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	interval := time.Duration(network.Document.Traffic.CellIntervalMillis) * time.Millisecond
	scheduler, err := fabric.NewScheduler(fabric.Config{
		Epoch: interval, CellsPerEpoch: 1,
		MaxLateness: time.Duration(network.Document.Traffic.MaxLatenessMillis) * time.Millisecond,
	}, &drainSource{drain: drain, sequence: sequence}, &uplinkSink{conn: conn, target: target})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "publishing to %s (%s) every %s\n",
		operator.ID, operator.Endpoint, interval)
	if err := scheduler.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func submitObject(queue *publish.Queue, path, publisherPath string) error {
	object, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(object) == 0 {
		return errors.New("refusing to publish an empty object")
	}
	// The site's *public* key. It says which site the object is published
	// under; the private half signs the object's manifest and never comes
	// near this command. A publication that named no site would be one a
	// reader could not attribute, so the queue refuses it.
	publisher, err := loadPublisherKey(publisherPath)
	if err != nil {
		return err
	}
	if err := queue.Submit(object, publisher); err != nil {
		return err
	}
	pending, err := queue.Pending()
	if err != nil {
		return err
	}
	// Deliberately the only thing printed: the byte count and the queue depth
	// are local facts the user already knows. Nothing here names the object.
	fmt.Fprintf(os.Stderr, "queued %d bytes; %d fragments pending\n", len(object), pending)
	return nil
}

// drainSource turns the deposit drain into the scheduler's cell source. Every
// tick seals a cell whether or not the queue had work: the drain returns cover
// on the identical code path, so what the tick emits is a function of the
// clock and never of the queue.
type drainSource struct {
	drain    *deposit.Drain
	sequence *uplink.FileSequence
}

func (source *drainSource) NextCell(context.Context) (fabric.Cell, error) {
	number, err := source.sequence.Next()
	if err != nil {
		// An exhausted or unreadable nonce space is not a lost cell. Sealing
		// past it would reuse a nonce, so it must stop the publisher; only a
		// reservation write that failed is local and transient.
		if !errors.Is(err, uplink.ErrSequenceWriteFailed) {
			return fabric.Cell{}, fmt.Errorf("uplink nonce space is unusable: %w", err)
		}
		return fabric.Cell{}, fmt.Errorf("%w: reserve uplink sequence: %w",
			fabric.ErrCellDropped, err)
	}
	return source.drain.Emit(number)
}

type uplinkSink struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (sink *uplinkSink) Send(ctx context.Context, cell fabric.Cell) error {
	deadline := time.Time{}
	if contextDeadline, ok := ctx.Deadline(); ok {
		deadline = contextDeadline
	}
	if err := sink.conn.SetWriteDeadline(deadline); err != nil {
		return classify("set write deadline", err)
	}
	written, err := sink.conn.WriteToUDP(cell[:], sink.target)
	if err != nil {
		return classify("write cell", err)
	}
	if written != fabric.CellSize {
		return classify("short UDP write",
			fmt.Errorf("wrote %d of %d bytes", written, fabric.CellSize))
	}
	return nil
}

// classify is the publisher's copy of the operator's rule, and it is the same
// rule for the same reason: a transient local failure costs the cell it
// interrupted, never the schedule, because a publisher that stopped on a full
// socket buffer would turn a local condition into an externally visible event.
// Only conditions that genuinely pass are lost cells; everything else stops
// the publisher and says why.
func classify(what string, cause error) error {
	if !sendFailureIsTransient(cause) {
		return fmt.Errorf("%s: %w", what, cause)
	}
	return fmt.Errorf("%w: %s: %w", fabric.ErrCellDropped, what, cause)
}

func sendFailureIsTransient(cause error) bool {
	if errors.Is(cause, os.ErrDeadlineExceeded) {
		return true
	}
	for _, transient := range []syscall.Errno{
		syscall.ENOBUFS, syscall.ENOMEM, syscall.EAGAIN,
		syscall.EINTR, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN,
	} {
		if errors.Is(cause, transient) {
			return true
		}
	}
	return false
}

func entryOperator(network topology.Verified, id string) (topology.Operator, error) {
	for _, operator := range network.Document.Operators {
		if operator.ID == id {
			return operator, nil
		}
	}
	return topology.Operator{}, fmt.Errorf("no operator %q in the signed topology", id)
}

func loadPublisherKey(path string) (ed25519.PublicKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, errors.New("publisher key is not base64")
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("publisher key is not an ed25519 public key")
	}
	return decoded, nil
}

func loadCommitteeKey(path string) (mix.PublicKey, error) {
	var key mix.PublicKey
	encoded, err := os.ReadFile(path)
	if err != nil {
		return key, err
	}
	decoded, err := decodeFixed(encoded, len(key))
	if err != nil {
		return key, fmt.Errorf("committee key: %w", err)
	}
	copy(key[:], decoded)
	return key, nil
}

// loadSessionSecret refuses a secret any other account can read, for the same
// reason an operator secret is refused: a shared uplink key that leaks lets a
// third party seal cells that the entry operator will accept as this
// publisher's.
func loadSessionSecret(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("uplink session secret must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("uplink session secret %s is readable by group or other; "+
			"its permissions must be 0600 or stricter", filepath.Base(path))
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	secret, err := decodeFixed(encoded, 32)
	if err != nil {
		return nil, fmt.Errorf("session secret: %w", err)
	}
	return secret, nil
}
