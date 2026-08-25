// Package node is the live network domain. Its import graph intentionally has
// no semantic-basin, reconstruction or browser package.
package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/bundle"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type Config struct {
	Topology      topology.Verified
	Secrets       topology.VerifiedSecrets
	ListenAddress string
	Cache         *rawcache.Store
	SequencePath  string
	HealthPath    string
	CacheSweep    time.Duration
	Seed          *bundle.Verified
}

type Stats struct {
	StartedAt      time.Time `json:"started_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	OperatorID     string    `json:"operator_id"`
	TopologyDigest string    `json:"topology_digest"`
	Sent           uint64    `json:"sent"`
	Received       uint64    `json:"received"`
	Stored         uint64    `json:"stored"`
	Relayed        uint64    `json:"relayed"`
	CoverSent      uint64    `json:"cover_sent"`
	WrongSize      uint64    `json:"wrong_size"`
	UnknownPeer    uint64    `json:"unknown_peer"`
	AuthRejected   uint64    `json:"auth_rejected"`
	ReplayRejected uint64    `json:"replay_rejected"`
	Duplicate      uint64    `json:"duplicate"`
	QueueDropped   uint64    `json:"queue_dropped"`
	CacheRejected  uint64    `json:"cache_rejected"`
	// SendDropped counts scheduled emissions lost to a local send failure.
	// It is the alarm that replaces the node stopping: a link that is
	// failing shows up here as a rising number while the cadence holds.
	SendDropped uint64 `json:"send_dropped"`
	// HealthDeferred counts health-file writes that failed. The file is
	// local observability, so a failure to write it must not be able to
	// stop the node that it exists to describe.
	HealthDeferred uint64 `json:"health_deferred"`
	// LastSentAt is when the most recent cell actually went out. It is the
	// liveness signal that has to exist now that a node no longer stops on a
	// local failure: a process that is up, on cadence, and emitting nothing
	// is invisible to a healthcheck that only asks whether it is up. An
	// observer on the wire reads this value directly off the link, so
	// publishing it gives away nothing that is not already public.
	LastSentAt time.Time `json:"last_sent_at"`
}

type counters struct {
	sent, received, stored, relayed, coverSent           atomic.Uint64
	wrongSize, unknownPeer, authRejected, replayRejected atomic.Uint64
	duplicate, queueDropped, cacheRejected               atomic.Uint64
	sendDropped, healthDeferred                          atomic.Uint64
	lastSentUnixNano                                     atomic.Int64
}

type Node struct {
	config    Config
	conn      *net.UDPConn
	queue     *fabric.QueueSource
	cover     *fabric.CoverSource
	sink      *authenticatedSink
	incoming  map[string]incomingPeer
	replay    map[uint16]*hop.ReplayWindow
	stats     *counters
	startedAt time.Time
}

type outgoingPeer struct {
	operator topology.Operator
	address  *net.UDPAddr
	key      [32]byte
}

type incomingPeer struct {
	operator topology.Operator
	key      [32]byte
}

type authenticatedSink struct {
	mu       sync.Mutex
	conn     *net.UDPConn
	self     topology.Operator
	peers    []outgoingPeer
	plan     []uint16
	next     uint64
	sequence *hop.FileSequence
	context  hop.Context
	stats    *counters
}

type coverSource struct{}

func (coverSource) NextCell(context.Context) (fabric.Cell, error) {
	cell, err := fabric.RandomCell()
	if err != nil {
		return fabric.Cell{}, err
	}
	if err := hop.SetMetadata(&cell, hop.CoverMetadata()); err != nil {
		return fabric.Cell{}, err
	}
	return cell, nil
}

func New(config Config) (*Node, error) {
	if config.Cache == nil {
		return nil, errors.New("raw cache is required")
	}
	if int(config.Secrets.Operator.Index) >= len(config.Topology.Document.Operators) ||
		config.Secrets.Operator.ID == "" ||
		config.Secrets.Operator.ID != config.Topology.Document.Operators[config.Secrets.Operator.Index].ID {
		return nil, errors.New("verified operator secrets do not match topology")
	}
	if config.ListenAddress == "" || config.SequencePath == "" || config.HealthPath == "" {
		return nil, errors.New("listen, sequence-state and health paths are required")
	}
	if config.CacheSweep <= 0 {
		return nil, errors.New("public cache sweep interval must be positive")
	}
	listen, err := net.ResolveUDPAddr("udp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", listen)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Node, error) {
		_ = conn.Close()
		return nil, err
	}
	queue, err := fabric.NewQueueSource(int(config.Topology.Document.Traffic.QueueCapacity))
	if err != nil {
		return fail(err)
	}
	sequence, err := hop.OpenFileSequence(config.SequencePath)
	if err != nil {
		return fail(err)
	}
	// Routing always comes from the signed topology, never from the copy carried
	// alongside local secrets.
	self := config.Topology.Document.Operators[config.Secrets.Operator.Index]
	outgoing := make([]outgoingPeer, 0, len(self.PeerPlan))
	peerOffset := make(map[uint16]uint16)
	plan := make([]uint16, len(self.PeerPlan))
	for index, peerIndex := range self.PeerPlan {
		offset, exists := peerOffset[peerIndex]
		if !exists {
			peer, _ := config.Topology.Operator(peerIndex)
			key, exists := config.Secrets.OutboundKeys[peerIndex]
			if !exists || key == ([32]byte{}) {
				return fail(fmt.Errorf("missing outbound key for signed peer %s", peer.ID))
			}
			address, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return fail(fmt.Errorf("resolve peer %s: %w", peer.ID, err))
			}
			offset = uint16(len(outgoing))
			peerOffset[peerIndex] = offset
			outgoing = append(outgoing, outgoingPeer{operator: peer, address: address, key: key})
		}
		plan[index] = offset
	}
	if len(config.Secrets.OutboundKeys) != len(outgoing) {
		return fail(errors.New("outbound key set differs from signed peer plan"))
	}
	incoming := make(map[string]incomingPeer)
	replay := make(map[uint16]*hop.ReplayWindow)
	incomingPeers := config.Topology.IncomingPeers(self.Index)
	for _, peer := range incomingPeers {
		address, err := net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return fail(fmt.Errorf("resolve incoming peer %s: %w", peer.ID, err))
		}
		key := udpAddressKey(address)
		if _, exists := incoming[key]; exists {
			return fail(errors.New("two incoming peers resolve to the same source endpoint"))
		}
		peerKey, exists := config.Secrets.InboundKeys[peer.Index]
		if !exists || peerKey == ([32]byte{}) {
			return fail(fmt.Errorf("missing inbound key for signed peer %s", peer.ID))
		}
		incoming[key] = incomingPeer{operator: peer, key: peerKey}
		replay[peer.Index] = &hop.ReplayWindow{}
	}
	if len(config.Secrets.InboundKeys) != len(incomingPeers) {
		return fail(errors.New("inbound key set differs from signed peer plan"))
	}
	stats := &counters{}
	sink := &authenticatedSink{
		conn: conn, self: self, peers: outgoing, plan: plan, sequence: sequence, stats: stats,
		context: hop.Context{
			TopologyDigest: config.Topology.Digest, NetworkID: config.Topology.Document.NetworkID,
			Epoch: config.Topology.Document.Epoch,
		},
	}
	cover := &fabric.CoverSource{Work: queue, Filler: coverSource{}}
	node := &Node{
		config: config, conn: conn, queue: queue, cover: cover, sink: sink,
		incoming: incoming, replay: replay, stats: stats, startedAt: time.Now().UTC(),
	}
	if config.Seed != nil {
		if err := node.seed(*config.Seed); err != nil {
			return fail(err)
		}
	}
	return node, nil
}

func (node *Node) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	interval := time.Duration(node.config.Topology.Document.Traffic.CellIntervalMillis) * time.Millisecond
	scheduler, err := fabric.NewScheduler(fabric.Config{
		Epoch: interval, CellsPerEpoch: 1,
		MaxLateness: time.Duration(node.config.Topology.Document.Traffic.MaxLatenessMillis) * time.Millisecond,
	}, node.cover, node.sink)
	if err != nil {
		return err
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsOut := make(chan error, 3)
	go func() { errorsOut <- node.receive(runContext) }()
	go func() { errorsOut <- node.maintain(runContext) }()
	go func() { errorsOut <- scheduler.Run(runContext) }()
	err = <-errorsOut
	cancel()
	_ = node.conn.Close()
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (node *Node) Snapshot() Stats {
	return Stats{
		StartedAt: node.startedAt, UpdatedAt: time.Now().UTC(), OperatorID: node.config.Secrets.Operator.ID,
		TopologyDigest: fmt.Sprintf("%x", node.config.Topology.Digest),
		Sent:           node.stats.sent.Load(), Received: node.stats.received.Load(), Stored: node.stats.stored.Load(),
		Relayed: node.stats.relayed.Load(), CoverSent: node.stats.coverSent.Load(),
		WrongSize: node.stats.wrongSize.Load(), UnknownPeer: node.stats.unknownPeer.Load(),
		AuthRejected: node.stats.authRejected.Load(), ReplayRejected: node.stats.replayRejected.Load(),
		Duplicate: node.stats.duplicate.Load(), QueueDropped: node.stats.queueDropped.Load(),
		CacheRejected: node.stats.cacheRejected.Load(),
		SendDropped:   node.stats.sendDropped.Load(), HealthDeferred: node.stats.healthDeferred.Load(),
		LastSentAt: lastSent(node.stats),
	}
}

func (sink *authenticatedSink) Send(ctx context.Context, cell fabric.Cell) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	metadata, err := hop.MetadataFromCell(cell)
	if err != nil {
		return fmt.Errorf("scheduler source supplied an invalid cell: %w", err)
	}
	// The peer counter advances before anything can fail, so which peer a
	// tick is addressed to stays a function of the tick index and the signed
	// plan. Holding it back on a failure would make the destination sequence
	// depend on local conditions, which is the shape of leak this whole path
	// exists to avoid.
	peer := sink.peers[sink.plan[sink.next%uint64(len(sink.plan))]]
	sink.next++
	sequence, err := sink.sequence.Next()
	if err != nil {
		// Reserving a hop sequence range writes to disk, so this is the
		// disk-full case reaching the emission path. Lose the cell.
		return sink.classify("reserve hop sequence", err)
	}
	sealContext := sink.context
	sealContext.Receiver = peer.operator.Index
	if err := hop.Seal(&cell, metadata, sink.self.Index, sequence, peer.key, sealContext); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := sink.conn.SetWriteDeadline(deadline); err != nil {
			return sink.classify("set write deadline", err)
		}
	} else if err := sink.conn.SetWriteDeadline(time.Time{}); err != nil {
		return sink.classify("set write deadline", err)
	}
	written, err := sink.conn.WriteToUDP(cell[:], peer.address)
	if err != nil {
		return sink.classify("write cell", err)
	}
	if written != fabric.CellSize {
		return sink.classify("short UDP write",
			fmt.Errorf("wrote %d of %d bytes", written, fabric.CellSize))
	}
	sink.stats.sent.Add(1)
	sink.stats.lastSentUnixNano.Store(time.Now().UTC().UnixNano())
	if hop.IsWork(metadata) {
		sink.stats.relayed.Add(1)
	} else {
		sink.stats.coverSent.Add(1)
	}
	return nil
}

// lastSent is the zero time until the node has emitted anything, so a
// healthcheck can tell "has not started" from "has stopped".
func lastSent(stats *counters) time.Time {
	nanoseconds := stats.lastSentUnixNano.Load()
	if nanoseconds == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanoseconds).UTC()
}

// sendFailureIsFatal decides whether one failed emission costs the schedule
// rather than a cell. Only a closed socket does: that is this node shutting
// down, and continuing to tick against a socket that is gone would leave it
// holding cadence forever, emitting nothing and reporting nothing wrong.
//
// Everything else is the host, and the host is not allowed a say in when this
// node emits. Exhausted socket buffers (ENOBUFS), a local rate limiter
// (EPERM), a route that went away (ENETUNREACH), a full disk under the hop
// sequence reservation: each costs the cell it interrupted and nothing else.
func sendFailureIsFatal(cause error) bool {
	return errors.Is(cause, net.ErrClosed)
}

// classify turns one failed emission into either a fatal error or a lost cell.
// A lost cell is never deferred, queued or re-emitted: a cell held back for a
// local reason and sent later is that local reason, on the wire.
func (sink *authenticatedSink) classify(what string, cause error) error {
	if sendFailureIsFatal(cause) {
		return fmt.Errorf("%s: %w", what, cause)
	}
	sink.stats.sendDropped.Add(1)
	return fmt.Errorf("%w: %s: %v", fabric.ErrCellDropped, what, cause)
}

func (node *Node) receive(ctx context.Context) error {
	buffer := make([]byte, fabric.CellSize+1)
	for {
		if err := node.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		count, source, err := node.conn.ReadFromUDP(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					continue
				}
			}
			return err
		}
		node.stats.received.Add(1)
		if count != fabric.CellSize {
			node.stats.wrongSize.Add(1)
			continue
		}
		peer, exists := node.incoming[udpAddressKey(source)]
		if !exists {
			node.stats.unknownPeer.Add(1)
			continue
		}
		var cell fabric.Cell
		copy(cell[:], buffer[:count])
		metadata, err := hop.Verify(cell, peer.operator.Index, peer.key, hop.Context{
			TopologyDigest: node.config.Topology.Digest, NetworkID: node.config.Topology.Document.NetworkID,
			Epoch: node.config.Topology.Document.Epoch, Receiver: node.config.Secrets.Operator.Index,
		})
		if err != nil {
			node.stats.authRejected.Add(1)
			continue
		}
		if err := node.replay[peer.operator.Index].Accept(metadata.Sequence); err != nil {
			node.stats.replayRejected.Add(1)
			continue
		}
		if !hop.IsWork(metadata) {
			continue
		}
		created, err := node.config.Cache.Put(metadata, hop.Ciphertext(cell))
		if err != nil {
			node.stats.cacheRejected.Add(1)
			continue
		}
		if !created {
			node.stats.duplicate.Add(1)
			continue
		}
		node.stats.stored.Add(1)
		if !node.queue.Enqueue(cell) {
			node.stats.queueDropped.Add(1)
		}
	}
}

func (node *Node) maintain(ctx context.Context) error {
	healthTicker := time.NewTicker(time.Second)
	cacheTicker := time.NewTicker(node.config.CacheSweep)
	defer healthTicker.Stop()
	defer cacheTicker.Stop()
	node.publishHealth()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-healthTicker.C:
			node.publishHealth()
		case <-cacheTicker.C:
			if err := node.enqueueCached(); err != nil {
				return err
			}
		}
	}
}

func (node *Node) seed(seed bundle.Verified) error {
	for ordinal, payload := range seed.Payloads {
		metadata, err := hop.WorkMetadata(seed.Stream, uint16(ordinal), uint16(len(seed.Payloads)))
		if err != nil {
			return err
		}
		_, err = node.config.Cache.Put(metadata, payload)
		if err != nil {
			return err
		}
		cell, err := hop.FromCiphertext(payload, metadata)
		if err != nil {
			return err
		}
		if !node.queue.Enqueue(cell) {
			return errors.New("public seed batch exceeds relay queue")
		}
	}
	return nil
}

func (node *Node) enqueueCached() error {
	streams, err := node.config.Cache.CompleteStreams()
	if err != nil {
		return err
	}
	for _, stream := range streams {
		payloads, complete, err := node.config.Cache.Load(stream)
		if err != nil {
			return err
		}
		if !complete {
			continue
		}
		for ordinal, payload := range payloads {
			metadata, _ := hop.WorkMetadata(stream, uint16(ordinal), uint16(len(payloads)))
			cell, err := hop.FromCiphertext(payload, metadata)
			if err != nil {
				return err
			}
			if !node.queue.Enqueue(cell) {
				node.stats.queueDropped.Add(1)
				return nil
			}
		}
	}
	return nil
}

// publishHealth writes the health file and counts a failure instead of
// returning it. The file is local observability; it is written on a full disk
// exactly when an operator most needs the node to still be running, and
// stopping the node because its status file could not be written would make a
// local disk condition into a network-visible outage.
func (node *Node) publishHealth() {
	if err := node.writeHealth(); err != nil {
		node.stats.healthDeferred.Add(1)
	}
}

func (node *Node) writeHealth() error {
	encoded, err := json.Marshal(node.Snapshot())
	if err != nil {
		return err
	}
	directory := filepath.Dir(node.config.HealthPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".health-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer func() { _ = os.Remove(path) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(path, node.config.HealthPath)
}

func udpAddressKey(address *net.UDPAddr) string {
	if address == nil {
		return ""
	}
	return net.JoinHostPort(address.IP.String(), fmt.Sprintf("%d", address.Port))
}
