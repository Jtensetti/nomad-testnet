// Package shaper owns the operator's fixed-rate egress schedule. It is kept in
// a separate OS process from receive/cache/relay production so useful-work CPU,
// disk I/O and Go-runtime scheduling cannot directly run on the scheduler's
// runtime. The only work input is a bounded nonblocking Unix datagram source.
package shaper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/relayipc"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type Config struct {
	Topology     topology.Verified
	Secrets      topology.VerifiedSecrets
	BindAddress  string
	WorkSocket   string
	SequencePath string
}

type Stats struct {
	Sent             uint64
	WorkSent         uint64
	CoverSent        uint64
	InvalidWorkInput uint64
}

type Shaper struct {
	config   Config
	conn     *net.UDPConn
	work     *relayipc.Source
	cover    *fabric.CoverSource
	sink     *authenticatedSink
	stats    *counters
	closed   atomic.Bool
}

type counters struct {
	sent      atomic.Uint64
	workSent  atomic.Uint64
	coverSent atomic.Uint64
}

type outgoingPeer struct {
	operator topology.Operator
	address  *net.UDPAddr
	key      [32]byte
}

type authenticatedSink struct {
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

func New(config Config) (*Shaper, error) {
	if int(config.Secrets.Operator.Index) >= len(config.Topology.Document.Operators) ||
		config.Secrets.Operator.ID == "" ||
		config.Secrets.Operator.ID != config.Topology.Document.Operators[config.Secrets.Operator.Index].ID {
		return nil, errors.New("verified operator secrets do not match topology")
	}
	if config.BindAddress == "" || config.WorkSocket == "" || config.SequencePath == "" {
		return nil, errors.New("bind address, work socket and sequence state are required")
	}
	bind, err := net.ResolveUDPAddr("udp", config.BindAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve shaper bind address: %w", err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Shaper, error) {
		_ = conn.Close()
		return nil, err
	}

	self := config.Topology.Document.Operators[config.Secrets.Operator.Index]
	outgoing := make([]outgoingPeer, 0, len(self.PeerPlan))
	peerOffset := make(map[uint16]uint16)
	plan := make([]uint16, len(self.PeerPlan))
	for index, peerIndex := range self.PeerPlan {
		offset, exists := peerOffset[peerIndex]
		if !exists {
			peer, err := config.Topology.Operator(peerIndex)
			if err != nil {
				return fail(err)
			}
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
	if len(outgoing) == 0 || len(config.Secrets.OutboundKeys) != len(outgoing) {
		return fail(errors.New("outbound key set differs from signed peer plan"))
	}
	sequence, err := hop.OpenFileSequence(config.SequencePath)
	if err != nil {
		return fail(err)
	}
	work, err := relayipc.Listen(config.WorkSocket, int(config.Topology.Document.Traffic.QueueCapacity))
	if err != nil {
		return fail(err)
	}
	stats := &counters{}
	sink := &authenticatedSink{
		conn: conn, self: self, peers: outgoing, plan: plan, sequence: sequence, stats: stats,
		context: hop.Context{
			TopologyDigest: config.Topology.Digest,
			NetworkID:      config.Topology.Document.NetworkID,
			Epoch:          config.Topology.Document.Epoch,
		},
	}
	cover := &fabric.CoverSource{Work: work, Filler: coverSource{}}
	return &Shaper{config: config, conn: conn, work: work, cover: cover, sink: sink, stats: stats}, nil
}

func (shaper *Shaper) Run(ctx context.Context) error {
	if shaper == nil || ctx == nil {
		return errors.New("shaper and context are required")
	}
	interval := time.Duration(shaper.config.Topology.Document.Traffic.CellIntervalMillis) * time.Millisecond
	scheduler, err := fabric.NewScheduler(fabric.Config{
		Epoch: interval, CellsPerEpoch: 1,
		MaxLateness: time.Duration(shaper.config.Topology.Document.Traffic.MaxLatenessMillis) * time.Millisecond,
	}, shaper.cover, shaper.sink)
	if err != nil {
		return err
	}
	err = scheduler.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (shaper *Shaper) Snapshot() Stats {
	if shaper == nil || shaper.stats == nil {
		return Stats{}
	}
	invalid := uint64(0)
	if shaper.work != nil {
		invalid = shaper.work.InvalidDatagrams()
	}
	return Stats{
		Sent: shaper.stats.sent.Load(), WorkSent: shaper.stats.workSent.Load(),
		CoverSent: shaper.stats.coverSent.Load(), InvalidWorkInput: invalid,
	}
}

func (shaper *Shaper) Close() error {
	if shaper == nil || !shaper.closed.CompareAndSwap(false, true) {
		return nil
	}
	var first error
	if shaper.work != nil {
		if err := shaper.work.Close(); err != nil {
			first = err
		}
	}
	if shaper.conn != nil {
		if err := shaper.conn.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (sink *authenticatedSink) Send(ctx context.Context, cell fabric.Cell) error {
	metadata, err := hop.MetadataFromCell(cell)
	if err != nil {
		return fmt.Errorf("shaper source supplied an invalid cell: %w", err)
	}
	peer := sink.peers[sink.plan[sink.next%uint64(len(sink.plan))]]
	sink.next++
	sequence, err := sink.sequence.Next()
	if err != nil {
		return err
	}
	wireContext := sink.context
	wireContext.Receiver = peer.operator.Index
	if err := hop.Seal(&cell, metadata, sink.self.Index, sequence, peer.key, wireContext); err != nil {
		return err
	}
	// Public network congestion may make a UDP send fail, but useful-work state
	// must not create retries or catch-up. One scheduler slot gets one datagram
	// send attempt of exactly CellSize bytes.
	if err := sink.conn.SetWriteDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
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
		sink.stats.workSent.Add(1)
	} else {
		sink.stats.coverSent.Add(1)
	}
	return nil
}
