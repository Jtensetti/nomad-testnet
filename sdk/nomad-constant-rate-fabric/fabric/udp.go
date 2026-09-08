package fabric

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDPSink consumes a peer-slot plan fixed at construction. Send has no
// destination-selection callback and therefore cannot consult private state.
type UDPSink struct {
	conn  *net.UDPConn
	peers []*net.UDPAddr
	plan  []uint16
	mu    sync.Mutex
	next  uint64
}

func NewUDPSink(conn *net.UDPConn, peers []*net.UDPAddr, plan []uint16) (*UDPSink, error) {
	if conn == nil {
		return nil, errors.New("UDP connection is required")
	}
	if len(peers) == 0 || len(plan) == 0 {
		return nil, errors.New("peers and public peer plan are required")
	}
	copiedPeers := make([]*net.UDPAddr, len(peers))
	for i, peer := range peers {
		if peer == nil {
			return nil, fmt.Errorf("peer %d is nil", i)
		}
		copiedPeers[i] = &net.UDPAddr{IP: append(net.IP(nil), peer.IP...), Port: peer.Port, Zone: peer.Zone}
	}
	copiedPlan := append([]uint16(nil), plan...)
	for i, slot := range copiedPlan {
		if int(slot) >= len(copiedPeers) {
			return nil, fmt.Errorf("plan entry %d selects missing peer slot %d", i, slot)
		}
	}
	return &UDPSink{conn: conn, peers: copiedPeers, plan: copiedPlan}, nil
}

func (s *UDPSink) Send(ctx context.Context, cell Cell) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		if err := s.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
	} else if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	slot := s.plan[s.next%uint64(len(s.plan))]
	s.next++
	n, err := s.conn.WriteToUDP(cell[:], s.peers[slot])
	if err != nil {
		return err
	}
	if n != CellSize {
		return fmt.Errorf("short UDP write: %d", n)
	}
	return nil
}

type Observation struct {
	ReceivedAt time.Time
	Size       int
	Source     string
	Digest     [32]byte
	Cell       Cell
}

// UDPObserver is a black-box receiver for wire tests. It observes datagrams,
// not scheduler callbacks or planned traces.
type UDPObserver struct {
	conn *net.UDPConn
}

func ListenUDPObserver(address *net.UDPAddr) (*UDPObserver, error) {
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, err
	}
	return &UDPObserver{conn: conn}, nil
}

func (o *UDPObserver) LocalAddr() *net.UDPAddr {
	if o == nil || o.conn == nil {
		return nil
	}
	addr, _ := o.conn.LocalAddr().(*net.UDPAddr)
	return addr
}

func (o *UDPObserver) Close() error {
	if o == nil || o.conn == nil {
		return nil
	}
	return o.conn.Close()
}

func (o *UDPObserver) Capture(ctx context.Context, count int) ([]Observation, error) {
	if o == nil || o.conn == nil {
		return nil, errors.New("observer is closed")
	}
	if count < 0 {
		return nil, errors.New("capture count must not be negative")
	}
	out := make([]Observation, 0, count)
	buffer := make([]byte, CellSize+1)
	for len(out) < count {
		if deadline, ok := ctx.Deadline(); ok {
			if err := o.conn.SetReadDeadline(deadline); err != nil {
				return nil, err
			}
		}
		n, source, err := o.conn.ReadFromUDP(buffer)
		if err != nil {
			return nil, err
		}
		if n != CellSize {
			return nil, fmt.Errorf("observed UDP payload has %d bytes, want %d", n, CellSize)
		}
		var cell Cell
		copy(cell[:], buffer[:n])
		out = append(out, Observation{
			ReceivedAt: time.Now(),
			Size:       n,
			Source:     source.String(),
			Digest:     sha256.Sum256(buffer[:n]),
			Cell:       cell,
		})
	}
	return out, nil
}
