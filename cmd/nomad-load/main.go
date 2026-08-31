// Command nomad-load floods one UDP endpoint at a fixed rate, for this
// project's own load gate and nothing else.
//
// PROD-14 claims a resource limit does not change what a node emits, and every
// measurement behind that claim was in-process. The claim needs the real stack
// under real load with a capture of a real interface, and nothing here
// generated load.
//
// It is deliberately NOT in the container image -- a release has no business
// carrying a flood generator -- so the gate runs it from the host against the
// compose bridge. cmd/nomad-load/image_test.go enforces that.
//
// It sends uniform random bytes of the cell size, which is the expensive case
// for the receiver: a wrong-size datagram is rejected on a length comparison,
// while a correctly sized one from an unrecognised source costs the peer
// lookup first. It authenticates against nothing, so the gate measures the
// cost of rejecting load rather than of carrying it.
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

// maximumRate bounds this: the gate needs thousands per second, and a tool
// that saturates a link because a flag had an extra digit eventually will.
const maximumRate = 200_000

type report struct {
	Target   string  `json:"target"`
	Rate     int     `json:"requested_rate_per_second"`
	Size     int     `json:"datagram_bytes"`
	Duration float64 `json:"duration_seconds"`
	Sent     uint64  `json:"sent"`
	Failed   uint64  `json:"failed"`
	Achieved float64 `json:"achieved_rate_per_second"`
	FirstErr string  `json:"first_error,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-load:", err)
		os.Exit(1)
	}
}

func run() error {
	target := flag.String("target", "", "host:port to send to")
	rate := flag.Int("rate", 0, "datagrams per second")
	duration := flag.Duration("duration", 0, "how long to send for")
	size := flag.Int("size", 1200, "datagram payload bytes")
	reportPath := flag.String("report", "", "write a JSON summary here")
	flag.Parse()

	if *target == "" {
		return errors.New("--target is required")
	}
	if *rate <= 0 || *rate > maximumRate {
		return fmt.Errorf("--rate must be between 1 and %d", maximumRate)
	}
	if *duration <= 0 {
		return errors.New("--duration must be positive")
	}
	if *size <= 0 || *size > 65507 {
		return errors.New("--size must be a legal UDP payload")
	}

	address, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", *target, err)
	}
	conn, err := net.DialUDP("udp", nil, address)
	if err != nil {
		return fmt.Errorf("dial %s: %w", *target, err)
	}
	defer func() { _ = conn.Close() }()

	payload := make([]byte, *size)
	if _, err := rand.Read(payload); err != nil {
		return err
	}

	// Bursts on a ticker, not one datagram per tick: at thousands a second a
	// per-datagram timer costs more than the send, and would measure itself.
	const tick = 5 * time.Millisecond
	perTick := *rate * int(tick) / int(time.Second)
	if perTick < 1 {
		perTick = 1
	}
	summary := report{Target: *target, Rate: *rate, Size: *size}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	started := time.Now()
	deadline := started.Add(*duration)
	for now := range ticker.C {
		if !now.Before(deadline) {
			break
		}
		for index := 0; index < perTick; index++ {
			if _, err := conn.Write(payload); err != nil {
				summary.Failed++
				if summary.FirstErr == "" {
					summary.FirstErr = err.Error()
				}
				continue
			}
			summary.Sent++
		}
	}
	elapsed := time.Since(started).Seconds()
	summary.Duration = elapsed
	if elapsed > 0 {
		summary.Achieved = float64(summary.Sent) / elapsed
	}

	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	if *reportPath != "" {
		if err := os.WriteFile(*reportPath, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
	}
	// A run that sent nothing measured nothing; the gate must not infer that
	// from a zero.
	if summary.Sent == 0 {
		return fmt.Errorf("sent no datagrams to %s in %s", *target, *duration)
	}
	return nil
}
