// Package wire records what a passive observer of a Nomad sender would see,
// in the exact text form the preregistered analysis harness parses.
//
// Emitting the capture in tcpdump's format rather than computing verdicts in
// Go is deliberate: the decision rule lives in one place
// (scripts/two-world-analysis.py, mirroring PREREGISTRATION.md), so a Go
// campaign and a real pcap campaign are judged by the same code. A second
// implementation of the statistics would be free to drift, and the direction
// it would drift is toward agreeing that two worlds match.
package wire

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// Packet is one observed datagram.
type Packet struct {
	At          time.Time
	Size        int
	Source      string
	Destination string
}

// Capture is an ordered set of observations from one world.
type Capture struct {
	Label   string
	Packets []Packet
}

func (capture *Capture) Add(packet Packet) {
	capture.Packets = append(capture.Packets, packet)
}

// WriteTcpdump renders the capture as `tcpdump -tt -nn` output. Timestamps
// are seconds since the Unix epoch with microsecond precision, matching what
// tcpdump prints, so the same parser reads both.
func (capture *Capture) WriteTcpdump(writer io.Writer) error {
	packets := append([]Packet(nil), capture.Packets...)
	sort.Slice(packets, func(i, j int) bool { return packets[i].At.Before(packets[j].At) })
	if _, err := fmt.Fprintf(writer,
		"reading from file %s, link-type EN10MB (Ethernet)\n", capture.Label); err != nil {
		return err
	}
	for _, packet := range packets {
		seconds := float64(packet.At.UnixNano()) / float64(time.Second)
		if _, err := fmt.Fprintf(writer, "%.6f IP %s > %s: UDP, length %d\n",
			seconds, packet.Source, packet.Destination, packet.Size); err != nil {
			return err
		}
	}
	return nil
}

// Interarrivals returns the gaps between consecutive observations.
func (capture *Capture) Interarrivals() []time.Duration {
	packets := append([]Packet(nil), capture.Packets...)
	sort.Slice(packets, func(i, j int) bool { return packets[i].At.Before(packets[j].At) })
	gaps := make([]time.Duration, 0, len(packets))
	for index := 1; index < len(packets); index++ {
		gaps = append(gaps, packets[index].At.Sub(packets[index-1].At))
	}
	return gaps
}

// MaxBurst is the largest number of observations inside any window.
func (capture *Capture) MaxBurst(window time.Duration) int {
	packets := append([]Packet(nil), capture.Packets...)
	sort.Slice(packets, func(i, j int) bool { return packets[i].At.Before(packets[j].At) })
	best, start := 0, 0
	for end := range packets {
		for packets[end].At.Sub(packets[start].At) > window {
			start++
		}
		if end-start+1 > best {
			best = end - start + 1
		}
	}
	return best
}

// Sizes returns the distinct observed datagram sizes.
func (capture *Capture) Sizes() []int {
	seen := map[int]struct{}{}
	for _, packet := range capture.Packets {
		seen[packet.Size] = struct{}{}
	}
	sizes := make([]int, 0, len(seen))
	for size := range seen {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)
	return sizes
}

// Destinations returns the distinct observed destinations.
func (capture *Capture) Destinations() []string {
	seen := map[string]struct{}{}
	for _, packet := range capture.Packets {
		seen[packet.Destination] = struct{}{}
	}
	destinations := make([]string, 0, len(seen))
	for destination := range seen {
		destinations = append(destinations, destination)
	}
	sort.Strings(destinations)
	return destinations
}
