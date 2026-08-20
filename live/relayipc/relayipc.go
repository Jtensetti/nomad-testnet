// Package relayipc is the one-way local handoff from the receive/cache process
// to the fixed-rate shaper process. The handoff is deliberately best-effort:
// if the bounded kernel queue cannot accept work immediately, the work is
// dropped and the independently scheduled shaper emits cover. There is no
// retry, catch-up, backpressure into the shaper, or private query API.
package relayipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"golang.org/x/sys/unix"
)

// Client is the producer side. Multiple node goroutines may call Enqueue; the
// mutex is entirely outside the shaper process and can only reduce useful work
// delivery, never delay a scheduled wire slot.
type Client struct {
	mu   sync.Mutex
	conn *net.UnixConn
	raw  syscallConn
}

// Source is the single-consumer shaper side. NextCell performs exactly one
// nonblocking recv attempt per scheduler request. It never waits for a producer.
type Source struct {
	conn    *net.UnixConn
	raw     syscallConn
	path    string
	invalid atomic.Uint64
}

type syscallConn interface {
	Read(func(fd uintptr) (done bool)) error
	Write(func(fd uintptr) (done bool)) error
}

func Dial(path string) (*Client, error) {
	if err := validateSocketPath(path, true); err != nil {
		return nil, err
	}
	address := &net.UnixAddr{Name: path, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, address)
	if err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Client{conn: conn, raw: raw}, nil
}

// Enqueue attempts one nonblocking datagram write. False means the shaper was
// unavailable or its bounded queue was full. Callers must not retry in response
// to private state; public maintenance can offer the work again only on its next
// already-scheduled maintenance cycle.
func (client *Client) Enqueue(cell fabric.Cell) bool {
	if client == nil || client.conn == nil || client.raw == nil {
		return false
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	written := 0
	var writeErr error
	controlErr := client.raw.Write(func(fd uintptr) bool {
		written, writeErr = unix.Write(int(fd), cell[:])
		// EAGAIN is a completed best-effort attempt, not permission to wait for
		// writability. Returning true keeps the Go runtime from polling.
		return true
	})
	return controlErr == nil && writeErr == nil && written == fabric.CellSize
}

func (client *Client) Close() error {
	if client == nil || client.conn == nil {
		return nil
	}
	return client.conn.Close()
}

func Listen(path string, capacity int) (*Source, error) {
	if capacity < 1 || capacity > 65_536 {
		return nil, errors.New("relay IPC capacity is outside supported bounds")
	}
	if err := validateSocketPath(path, false); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("relay IPC parent must be a real directory")
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 || existing.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("relay IPC path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	address := &net.UnixAddr{Name: path, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", address)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Source, error) {
		_ = conn.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fail(err)
	}
	// This is an upper target, not an unbounded queue. The kernel may clamp it
	// to a lower public system limit; either way producers still use one
	// nonblocking datagram attempt and fail toward cover.
	if err := conn.SetReadBuffer(capacity * fabric.CellSize); err != nil {
		return fail(err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fail(err)
	}
	return &Source{conn: conn, raw: raw, path: path}, nil
}

func (source *Source) NextCell(ctx context.Context) (fabric.Cell, error) {
	if source == nil || source.conn == nil || source.raw == nil {
		return fabric.Cell{}, fabric.ErrNoWork
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return fabric.Cell{}, ctx.Err()
		default:
		}
	}
	var cell fabric.Cell
	received := 0
	var recvErr error
	controlErr := source.raw.Read(func(fd uintptr) bool {
		received, _, recvErr = unix.Recvfrom(int(fd), cell[:], unix.MSG_DONTWAIT)
		// Never ask the runtime poller to wait for a producer. One syscall is the
		// complete work lookup for this public scheduler slot.
		return true
	})
	if controlErr != nil {
		return fabric.Cell{}, controlErr
	}
	if errors.Is(recvErr, unix.EAGAIN) || errors.Is(recvErr, unix.EWOULDBLOCK) {
		return fabric.Cell{}, fabric.ErrNoWork
	}
	if recvErr != nil {
		return fabric.Cell{}, recvErr
	}
	if received != fabric.CellSize {
		source.invalid.Add(1)
		return fabric.Cell{}, fabric.ErrNoWork
	}
	return cell, nil
}

func (source *Source) InvalidDatagrams() uint64 {
	if source == nil {
		return 0
	}
	return source.invalid.Load()
}

func (source *Source) Close() error {
	if source == nil {
		return nil
	}
	var closeErr error
	if source.conn != nil {
		closeErr = source.conn.Close()
	}
	if source.path != "" {
		if err := os.Remove(source.path); err != nil && !errors.Is(err, os.ErrNotExist) && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func validateSocketPath(path string, mustExist bool) error {
	if path == "" || !filepath.IsAbs(path) || len(path) > 96 {
		return errors.New("relay IPC path must be a short absolute filesystem path")
	}
	if mustExist {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("relay IPC target is not a real Unix datagram socket")
		}
	}
	return nil
}
