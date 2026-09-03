// Package entry is the entry operator's service: the daemon that terminates
// publisher uplinks and feeds the deposit mailbox.
//
// Until now this role had no process. The responder existed and was exercised,
// the airlock existed and was exercised, and nothing ran them together, so
// every property of the publication path was established inside one test binary
// where the publisher, the operator and the committee shared an address space.
// PUBLICATION_INGRESS.md said so in as many words: "no daemon runs it against
// the deposit mailbox".
//
// What that cost was not correctness -- the parts were tested -- but boundary.
// A claim about what an entry operator can observe is a claim about a process
// that receives datagrams from strangers, and it cannot be evidenced by a
// function call.
//
// # What this service must never learn
//
// It terminates uplinks and it must not learn who is publishing. The handshake
// is one-sided by design: a publisher authenticates the operator and proves
// nothing about itself. Everything that bounds abuse here is per session rather
// than per identity, and deposit slots are derived from (session, sequence)
// inside the airlock so that one depositor can neither name nor squat
// another's.
//
// It also cannot tell work from cover, and does not try. The inner layer is
// encrypted to the committee; only threshold decryption reveals which columns
// were the reserved empty fragment, and by then the shuffle chain has destroyed
// the link to whoever deposited them. An entry operator that could distinguish
// them would be a publisher-to-object mapping by itself.
package entry

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/deposit"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// Config is everything the service needs, all of it already verified.
type Config struct {
	Topology topology.Verified
	// KEX is this operator's key-agreement private key. It is the only secret
	// the service holds: the uplink is one-sided, so there is nothing to
	// authenticate a publisher with and nothing to sign.
	KEX *ecdh.PrivateKey
	// Committee comes from a DKG certificate verified against the topology,
	// not from a bare key file, so the key a deposit is encrypted to is
	// authenticated by the same operators that signed the epoch.
	Committee     mix.ThresholdCommittee
	ListenAddress string
	// BatchDirectory is where sealed batches are written for the shuffle
	// chain to collect. This service does not mix; it fills the mailbox.
	BatchDirectory string
	HealthPath     string
	Schedule       airlock.Schedule
	// SessionLimit bounds how many uplink sessions this service will
	// establish, for as long as it runs. Accepting handshakes without a bound
	// turns a cheap cell into unbounded state, which is the whole reason the
	// responder takes a limit.
	//
	// It is a budget spent, not an occupancy: the responder must remember every
	// ephemeral key it has accepted or a replayed handshake would establish a
	// second session on the same key and the same AEAD nonces, so nothing can
	// give a slot back. Once the budget is gone this operator establishes no
	// further sessions until it is restarted, and a service is restarted at
	// each topology epoch because the uplink context it was built with names
	// one. Size it for the publishers an epoch is expected to carry, with
	// headroom: an adversary can spend the budget with that many cheap cells,
	// and the refusal that follows is silent and fail-closed by design.
	SessionLimit int
}

// Stats is what an operator can see about its own service. Every counter here
// is about cells and sessions; none of it is about publishers, because the
// service does not know any.
type Stats struct {
	StartedAt time.Time `json:"started_at"`
	// UpdatedAt is when this snapshot was written. A health check reads it to
	// tell a service that is reporting from one that stopped.
	UpdatedAt  time.Time `json:"updated_at"`
	OperatorID string    `json:"operator_id"`
	// Received counts datagrams that arrived, whatever became of them.
	Received uint64 `json:"received"`
	// WrongSize counts datagrams that were not exactly one cell. They are
	// refused before anything looks at their contents.
	WrongSize uint64 `json:"wrong_size"`
	// Handshakes counts sessions established.
	Handshakes uint64 `json:"handshakes"`
	// HandshakesRefused counts handshakes refused for any reason: a replayed
	// ephemeral key, the session limit, or a cell that was not a handshake
	// from an address with no session.
	HandshakesRefused uint64 `json:"handshakes_refused"`
	// Accepted counts cells that opened under a session and were handed to the
	// mailbox. It does not distinguish work from cover, because the service
	// cannot, and it deliberately does not report whether the airlock kept
	// them: a full epoch and an exhausted per-session quota are both silent by
	// design, because a count that revealed them would be an occupancy oracle.
	Accepted uint64 `json:"accepted"`
	// RefusedCell counts cells that failed to open under the session their
	// address is bound to. This is the counter an operator watches: it is the
	// one an attacker moves.
	RefusedCell uint64 `json:"refused_cell"`
	// OutsideWindow counts cells that opened correctly but arrived when no
	// deposit window was open -- after the cutoff, or between the seal and the
	// next epoch. It is separated from RefusedCell because the two mean
	// opposite things: this one is the ordinary consequence of a publisher
	// emitting at a constant cadence across a schedule that closes, and
	// lumping it in with authentication failures would bury the signal that
	// matters under routine traffic.
	//
	// It is also the counter that measures how much publication work the
	// current implementation destroys: see DEC-020.
	OutsideWindow uint64 `json:"outside_window"`
	// Conflicted counts cells that opened and were refused because their
	// deposit slot already holds a different payload. A publisher that
	// re-sealed a fragment rather than retransmitting the sealed cell produces
	// exactly this, so a non-zero count here is diagnostic rather than
	// adversarial.
	Conflicted uint64 `json:"conflicted"`
	// Sealed counts release epochs sealed and written.
	Sealed uint64 `json:"sealed"`
	// LastSealedAt is when the most recent batch was written. It is the
	// liveness signal: a service that is up and sealing nothing is a service
	// whose mailbox is not moving.
	LastSealedAt time.Time `json:"last_sealed_at"`
}

// Service is a running entry operator.
type Service struct {
	config    Config
	responder *uplink.Responder
	ingress   *deposit.Ingress
	airlock   *airlock.Airlock

	mu sync.Mutex
	// sessions maps a peer address to the session established from it.
	//
	// A data cell carries no session identifier -- putting one on the wire
	// would be a linkable tag on every cell a publisher sends -- so the
	// association has to come from somewhere the operator already knows, and
	// the source address is the only such thing. It reveals nothing new: UDP
	// hands the operator the address whether it uses it or not.
	//
	// The alternative, trial-decrypting each cell against every held session,
	// avoids depending on the address but costs one AEAD open per session per
	// cell, and makes a forged cell cost the operator its whole session table.
	// That is a denial-of-service amplifier bought to hide something the
	// operator can see anyway.
	//
	// An address maps to a short list rather than to one session, because one
	// session per address made the first binder of an address its owner for the
	// life of the process. A publisher that restarted behind a NAT that kept
	// its mapping came back on the same address with a new ephemeral key, its
	// handshake was tried as a data cell against the session it no longer held,
	// failed to open, and was counted as a refusal -- with no way back, since a
	// bound address never reached the responder again. Anyone who could put a
	// datagram on the wire with a victim's source address could do the same on
	// purpose.
	//
	// The list is capped at maxSessionsPerAddress and full is refused rather
	// than evicted: evicting the oldest would hand that lockout back to an
	// attacker in a different shape. The cap is what keeps the trial-open cost
	// bounded -- a forged cell costs at most that many AEAD opens, not the
	// whole table.
	//
	// Falling through to the responder also means a cell that opens under none
	// of an address's sessions now costs a key agreement rather than an AEAD
	// open. That does not raise the ceiling: source addresses are free, so a
	// flood from unbound addresses already cost one key agreement per datagram
	// and still does. What it removes is the attacker's need to vary them.
	//
	// The cost is that a publisher whose NAT rebinds loses its session and has
	// to handshake again. That is a real limitation and it is recorded rather
	// than hidden.
	sessions map[string][]*boundSession

	stats     statsCounters
	startedAt time.Time
	lastSeal  atomic.Int64
}

type boundSession struct {
	session   *uplink.Session
	sessionID [32]byte
}

// maxSessionsPerAddress bounds how many uplink sessions one source address may
// hold at once. It is small on purpose: it exists so a restart or a spoofed
// datagram cannot take an address away from its publisher, not so an address
// can accumulate sessions.
const maxSessionsPerAddress = 4

type statsCounters struct {
	received, wrongSize, handshakes, refusedHandshakes atomic.Uint64
	accepted, refusedCell, outsideWindow, conflicted   atomic.Uint64
	sealed                                             atomic.Uint64
}

// New builds the service. Everything it validates here is a configuration
// error rather than a runtime one: a service that starts and then cannot
// accept anything is worse than one that refuses to start.
func New(config Config) (*Service, error) {
	if config.KEX == nil {
		return nil, errors.New("entry operator key-agreement private key is required")
	}
	if config.ListenAddress == "" {
		return nil, errors.New("listen address is required")
	}
	if config.BatchDirectory == "" {
		return nil, errors.New("batch directory is required: a sealed batch nobody can " +
			"collect is a deposit window that discards its own work")
	}
	if config.SessionLimit < 1 {
		return nil, errors.New("session limit must be positive")
	}
	operator, err := selfOperator(config.Topology, config.KEX)
	if err != nil {
		return nil, err
	}
	uplinkContext := uplink.Context{
		NetworkID:      config.Topology.Document.NetworkID,
		Epoch:          config.Topology.Document.Epoch,
		TopologyDigest: config.Topology.Digest,
		EntryOperator:  operator.Index,
	}
	responder, err := uplink.NewResponder(config.KEX, config.Committee.PublicKey,
		uplinkContext, config.SessionLimit)
	if err != nil {
		return nil, err
	}
	if err := config.Schedule.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.BatchDirectory, 0o700); err != nil {
		return nil, err
	}
	// The airlock is per release epoch and rolls; Run builds the first one for
	// whichever epoch is open when the service starts, so a service started
	// mid-epoch joins the window in progress rather than inventing one.
	return &Service{
		config: config, responder: responder,
		sessions: map[string][]*boundSession{},
	}, nil
}

// selfOperator finds this service's own entry in the signed topology by the
// key-agreement key it holds.
//
// Matching on the key rather than on a configured identifier means a service
// cannot be told it is an operator it has no key for: the uplink context binds
// the entry operator's index, so a misconfigured index would produce a service
// whose handshakes silently never open.
func selfOperator(network topology.Verified, kex *ecdh.PrivateKey) (topology.Operator, error) {
	want := base64.StdEncoding.EncodeToString(kex.PublicKey().Bytes())
	for _, operator := range network.Document.Operators {
		if operator.KEXKey == want {
			return operator, nil
		}
	}
	return topology.Operator{}, errors.New("the signed topology names no operator holding " +
		"this key-agreement key, so this service has no place in this epoch")
}

// Run serves until the context is cancelled.
//
// Both goroutines are drained before returning. Returning as soon as the first
// one exits would leave the other writing to the batch directory and the health
// file of a service the caller believes has stopped.
func (service *Service) Run(ctx context.Context) error {
	address, err := net.ResolveUDPAddr("udp", service.config.ListenAddress)
	if err != nil {
		return err
	}
	socket, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer func() { _ = socket.Close() }()

	service.startedAt = time.Now().UTC()
	now := service.startedAt
	epoch, err := service.config.Schedule.EpochAt(now)
	if err != nil {
		return fmt.Errorf("no release epoch is open: %w", err)
	}
	if err := service.rollTo(epoch); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		// Unblocks the read: a UDP read has no deadline of its own and the
		// context cannot interrupt it.
		_ = socket.Close()
	}()

	var group sync.WaitGroup
	errs := make(chan error, 2)
	group.Add(2)
	go func() { defer group.Done(); errs <- service.receive(ctx, socket) }()
	go func() { defer group.Done(); errs <- service.maintain(ctx) }()
	group.Wait()
	close(errs)

	for err := range errs {
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}

func (service *Service) receive(ctx context.Context, socket *net.UDPConn) error {
	buffer := make([]byte, fabric.CellSize+1)
	for {
		read, from, err := socket.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		service.stats.received.Add(1)
		// A datagram that is not exactly one cell is refused before anything
		// looks at its contents. Every uplink cell is the same size, so a
		// different size is not a malformed cell, it is not a cell.
		if read != fabric.CellSize {
			service.stats.wrongSize.Add(1)
			continue
		}
		var cell fabric.Cell
		copy(cell[:], buffer[:read])
		service.handle(cell, from, time.Now().UTC())
	}
}

// handle routes one cell. It is tried against the sessions already bound to its
// source address, and offered to the responder as a handshake if none of them
// open it.
//
// Trying the sessions first matters: a handshake is 1200 bytes with an 8-byte
// counter like every other cell, so the two are indistinguishable on the wire
// and the order of attempts is the only thing that decides which a cell is
// treated as. A cell that opened under a session is never offered to the
// responder, so an opened cell is deposited once and only once.
func (service *Service) handle(cell fabric.Cell, from *net.UDPAddr, now time.Time) {
	key := from.String()
	service.mu.Lock()
	bound := service.sessions[key]
	mailbox := service.ingress
	service.mu.Unlock()

	for _, held := range bound {
		err := mailbox.Accept(held.session, held.sessionID, cell, now)
		if errors.Is(err, deposit.ErrCellRefused) {
			continue
		}
		switch {
		case err == nil:
			service.stats.accepted.Add(1)
		case errors.Is(err, deposit.ErrNotForThisEpoch):
			service.stats.outsideWindow.Add(1)
		case errors.Is(err, airlock.ErrDepositConflict):
			service.stats.conflicted.Add(1)
		default:
			service.stats.refusedCell.Add(1)
		}
		return
	}

	// The per-address cap is checked before the responder is asked, so an
	// address that is full cannot spend the operator's session budget on a
	// handshake it would then have nowhere to put.
	if len(bound) >= maxSessionsPerAddress {
		service.stats.refusedHandshakes.Add(1)
		return
	}
	session, sessionID, err := service.responder.Accept(cell)
	if err != nil {
		// A cell from an address that holds sessions and opened under none of
		// them is a refused cell, not a refused handshake: it is the counter an
		// operator watches, and an attacker sending garbage at an established
		// publisher's address must not be able to move it somewhere quieter.
		if len(bound) > 0 {
			service.stats.refusedCell.Add(1)
		} else {
			service.stats.refusedHandshakes.Add(1)
		}
		return
	}
	service.mu.Lock()
	// Newest first: a publisher that just handshaked is the one sending, so the
	// common case still costs one open. The lock is held against the epoch roll
	// in maintain, which swaps the mailbox under the same mutex; handle itself
	// runs only on the receive goroutine, so the cap checked above cannot have
	// moved. Appending onto a fresh slice rather than in place is what lets the
	// trial-open loop above read its copy without the lock.
	service.sessions[key] = append([]*boundSession{
		{session: session, sessionID: sessionID}}, service.sessions[key]...)
	service.mu.Unlock()
	service.stats.handshakes.Add(1)
}

// maintain seals the deposit window when it closes and rolls to the next
// release epoch. It runs on a timer that has nothing to do with what arrives,
// because the schedule is public and the deposit window must close at the same
// instant whether the mailbox is full or empty.
func (service *Service) maintain(ctx context.Context) error {
	interval := service.config.Schedule.Period / 20
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// One last attempt to seal, so work already deposited is not
			// discarded because the process was asked to stop.
			service.sealIfDue(time.Now().UTC())
			service.publishHealth()
			return nil
		case <-ticker.C:
			now := time.Now().UTC()
			service.sealIfDue(now)
			epoch, err := service.config.Schedule.EpochAt(now)
			if err != nil {
				// Past the schedule's last epoch. The service keeps running
				// and stops accepting rather than exiting: an operator that
				// vanished at an epoch boundary would take its peers'
				// diagnosis with it.
				service.publishHealth()
				continue
			}
			if epoch != service.currentEpoch() {
				if err := service.rollTo(epoch); err != nil {
					return err
				}
			}
			service.publishHealth()
		}
	}
}

func (service *Service) currentEpoch() uint64 {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.airlock.Epoch()
}

// sealIfDue seals the open window once its cutoff has passed and writes the
// batch where the shuffle chain can collect it.
func (service *Service) sealIfDue(now time.Time) {
	service.mu.Lock()
	mailbox := service.airlock
	service.mu.Unlock()
	if mailbox == nil || mailbox.Sealed() {
		return
	}
	sealed, err := mailbox.Seal(now)
	if err != nil {
		// Before the cutoff, or after the release: neither is an error the
		// service can act on, and both are the ordinary state for most of an
		// epoch.
		return
	}
	if err := service.writeBatch(sealed); err != nil {
		// A batch that cannot be written is lost work, and the service says so
		// rather than continuing quietly, but it does not stop: the next epoch
		// may well write fine, and an operator that exits here takes its own
		// liveness signal down with it.
		fmt.Fprintf(os.Stderr, "nomad-entry: release epoch %d could not be written: %v\n",
			sealed.ReleaseEpoch, err)
		return
	}
	service.stats.sealed.Add(1)
	service.lastSeal.Store(now.UnixNano())
}

func (service *Service) rollTo(epoch uint64) error {
	mailbox, err := airlock.New(service.config.Schedule, service.config.Committee, epoch)
	if err != nil {
		return err
	}
	ingress, err := deposit.NewIngress(mailbox)
	if err != nil {
		return err
	}
	service.mu.Lock()
	service.airlock = mailbox
	service.ingress = ingress
	service.mu.Unlock()
	return nil
}

// sealedBatch is the published form of one release epoch's columns.
//
// It carries no deposit identifiers, no session identifiers and no arrival
// order: the columns are already ordered by deposit ID and randomly placed, so
// what reaches the chain says nothing about who deposited or when.
type sealedBatch struct {
	ReleaseEpoch uint64   `json:"release_epoch"`
	Digest       string   `json:"digest"`
	Columns      []string `json:"columns"`
}

func (service *Service) writeBatch(sealed airlock.Sealed) error {
	document := sealedBatch{
		ReleaseEpoch: sealed.ReleaseEpoch,
		Digest:       base64.StdEncoding.EncodeToString(sealed.Digest[:]),
		Columns:      make([]string, 0, len(sealed.Columns)),
	}
	for _, column := range sealed.Columns {
		document.Columns = append(document.Columns,
			base64.StdEncoding.EncodeToString(column[:]))
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	name := fmt.Sprintf("release-%020d.json", sealed.ReleaseEpoch)
	final := filepath.Join(service.config.BatchDirectory, name)
	// Written to a temporary name and renamed, so a collector never reads a
	// half-written batch.
	temporary := final + ".partial"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, final)
}

// Snapshot is what the service knows about itself.
func (service *Service) Snapshot() Stats {
	operator, _ := selfOperator(service.config.Topology, service.config.KEX)
	stats := Stats{
		StartedAt:         service.startedAt,
		UpdatedAt:         time.Now().UTC(),
		OperatorID:        operator.ID,
		Received:          service.stats.received.Load(),
		WrongSize:         service.stats.wrongSize.Load(),
		Handshakes:        service.stats.handshakes.Load(),
		HandshakesRefused: service.stats.refusedHandshakes.Load(),
		Accepted:          service.stats.accepted.Load(),
		RefusedCell:       service.stats.refusedCell.Load(),
		OutsideWindow:     service.stats.outsideWindow.Load(),
		Conflicted:        service.stats.conflicted.Load(),
		Sealed:            service.stats.sealed.Load(),
	}
	if nanos := service.lastSeal.Load(); nanos != 0 {
		stats.LastSealedAt = time.Unix(0, nanos).UTC()
	}
	return stats
}

func (service *Service) publishHealth() {
	if service.config.HealthPath == "" {
		return
	}
	encoded, err := json.MarshalIndent(service.Snapshot(), "", "  ")
	if err != nil {
		return
	}
	encoded = append(encoded, '\n')
	temporary := service.config.HealthPath + ".partial"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return
	}
	_ = os.Rename(temporary, service.config.HealthPath)
}
