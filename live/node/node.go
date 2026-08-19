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
	StartedAt       time.Time `json:"started_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	OperatorID      string    `json:"operator_id"`
	TopologyDigest string    `json:"topology_digest"`
	Sent            uint64    `json:"sent"`
	Received        uint64    `json:"received"`
	Stored          uint64    `json:"stored"`
	Relayed         uint64    `json:"relayed"`
	CoverSent       uint64    `json:"cover_sent"`
	WrongSize       uint64    `json:"wrong_size"`
	UnknownPeer     uint64    `json:"unknown_peer"`
	AuthRejected    uint64    `json:"auth_rejected"`
	ReplayRejected  uint64    `json:"replay_rejected"`
	Duplicate       uint64    `json:"duplicate"`
	QueueDropped    uint64    `json:"queue_dropped"`
	CacheRejected   uint64    `json:"cache_rejected"`
}

type counters struct {
	sent, received, stored, relayed, coverSent             atomic.Uint64
	wrongSize, unknownPeer, authRejected, replayRejected   atomic.Uint64
	duplicate, queueDropped, cacheRejected                 atomic.Uint64
}

type Node struct {
	config       Config
	conn         *net.UDPConn
	queue        *fabric.QueueSource
	cover        *fabric.CoverSource
	sink         *authenticatedSink
	incoming     map[string]incomingPeer
	replay       map[uint16]*hop.ReplayWindow
	stats        counters
	startedAt    time.Time
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
	self := config.Secrets.Operator
	outgoing := make([]outgoingPeer, 0, len(self.PeerPlan))
	peerOffset := make(map[uint16]uint16)
	plan := make([]uint16, len(self.PeerPlan))
	for index, peerIndex := range self.PeerPlan {
		offset, exists := peerOffset[peerIndex]
		if !exists {
			peer, _ := config.Topology.Operator(peerIndex)
			address, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return fail(fmt.Errorf("resolve peer %s: %w", peer.ID, err))
			}
			offset = uint16(len(outgoing))
			peerOffset[peerIndex] = offset
			outgoing = append(outgoing, outgoingPeer{operator: peer, address: address, key: config.Secrets.OutboundKeys[peerIndex]})
		}
		plan[index] = offset
	}
	incoming := make(map[string]incomingPeer)
	replay := make(map[uint16]*hop.ReplayWindow)
	for _, peer := range config.Topology.IncomingPeers(self.Index) {
		address, err := net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return fail(fmt.Errorf("resolve incoming peer %s: %w", peer.ID, err))
		}
		key := udpAddressKey(address)
		if _, exists := incoming[key]; exists {
			return fail(errors.New("two incoming peers resolve to the same source endpoint"))
		}
		incoming[key] = incomingPeer{operator: peer, key: config.Secrets.InboundKeys[peer.Index]}
		replay[peer.Index] = &hop.ReplayWindow{}
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
		incoming: incoming, replay: replay, stats: *stats, startedAt: time.Now().UTC(),
	}
	// Keep one shared counter object between sink and receiver.
	node.sink.stats = &node.stats
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
		Sent: node.stats.sent.Load(), Received: node.stats.received.Load(), Stored: node.stats.stored.Load(),
		Relayed: node.stats.relayed.Load(), CoverSent: node.stats.coverSent.Load(),
		WrongSize: node.stats.wrongSize.Load(), UnknownPeer: node.stats.unknownPeer.Load(),
		AuthRejected: node.stats.authRejected.Load(), ReplayRejected: node.stats.replayRejected.Load(),
		Duplicate: node.stats.duplicate.Load(), QueueDropped: node.stats.queueDropped.Load(),
		CacheRejected: node.stats.cacheRejected.Load(),
	}
}

func (sink *authenticatedSink) Send(ctx context.Context, cell fabric.Cell) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	metadata, err := hop.MetadataFromCell(cell)
	if err != nil {
		return fmt.Errorf("scheduler source supplied an invalid cell: %w", err)
	}
	peer := sink.peers[sink.plan[sink.next%uint64(len(sink.plan))]]
	sink.next++
	sequence, err := sink.sequence.Next()
	if err != nil {
		return err
	}
	context := sink.context
	context.Receiver = peer.operator.Index
	if err := hop.Seal(&cell, metadata, sink.self.Index, sequence, peer.key, context); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := sink.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
	} else if err := sink.conn.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	written, err := sink.conn.WriteToUDP(cell[:], peer.address)
	if err != nil {
		return err
	}
	if written != fabric.CellSize {
		return fmt.Errorf("short UDP write: %d", written)
	}
	sink.stats.sent.Add(1)
	if hop.IsWork(metadata) {
		sink.stats.relayed.Add(1)
	} else {
		sink.stats.coverSent.Add(1)
	}
	return nil
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
	if err := node.writeHealth(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-healthTicker.C:
			if err := node.writeHealth(); err != nil {
				return err
			}
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
