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
	// Segment is the contiguous observation window this packet belongs to.
	Segment int
}

// Capture is an ordered set of observations from one world.
//
// A campaign observes a world in several rounds, and between them the sender
// is not running: the observer sits idle while the other worlds take their
// turn. A capture is therefore a sequence of contiguous segments, not one
// stream, and the gap between two segments is the harness's scheduling rather
// than anything the sender did. Treating a whole capture as one stream makes
// every derived statistic a function of how long the other worlds took.
type Capture struct {
	Label   string
	Packets []Packet
	segment int
}

// BeginSegment starts a new contiguous observation window. Callers mark the
// start of every round; packets added afterwards belong to it.
func (capture *Capture) BeginSegment() {
	capture.segment++
}

func (capture *Capture) Add(packet Packet) {
	packet.Segment = capture.segment
	capture.Packets = append(capture.Packets, packet)
}

// Segments returns one capture per contiguous observation window, in order,
// each labelled with its index. Empty windows are omitted.
func (capture *Capture) Segments() []*Capture {
	grouped := map[int][]Packet{}
	for _, packet := range capture.Packets {
		grouped[packet.Segment] = append(grouped[packet.Segment], packet)
	}
	indices := make([]int, 0, len(grouped))
	for index := range grouped {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	segments := make([]*Capture, 0, len(indices))
	for position, index := range indices {
		segments = append(segments, &Capture{
			Label:   fmt.Sprintf("%s-r%d", capture.Label, position),
			Packets: grouped[index],
		})
	}
	return segments
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

// Interarrivals returns the gaps between consecutive observations within a
// segment. Gaps that span two segments are excluded: they measure how long the
// harness spent elsewhere, not the sender's cadence, and including them puts
// the other worlds' durations inside a statistic about this one.
func (capture *Capture) Interarrivals() []time.Duration {
	packets := append([]Packet(nil), capture.Packets...)
	sort.Slice(packets, func(i, j int) bool {
		if packets[i].Segment != packets[j].Segment {
			return packets[i].Segment < packets[j].Segment
		}
		return packets[i].At.Before(packets[j].At)
	})
	gaps := make([]time.Duration, 0, len(packets))
	for index := 1; index < len(packets); index++ {
		if packets[index].Segment != packets[index-1].Segment {
			continue
		}
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
