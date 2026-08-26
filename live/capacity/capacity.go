// Package capacity derives what a Nomad operator's configuration implies about
// throughput, and provides the shape a measurement of it is reported in.
//
// PROD-28 asked for three numbers -- cells per second per operator, objects per
// epoch, and concurrent publishers -- and the registry recorded that none of
// them existed. Two of the three turn out not to be measurements at all.
//
// A fixed-cadence fabric does not have a throughput in the usual sense. An
// operator emits exactly one cell per interval per link whether it has work or
// not, so "cells per second per operator" is a fact about the signed topology,
// not about the hardware. What the hardware decides is something different and
// more useful: whether the node can finish the per-cell work inside the
// interval, and by what margin. That margin is the number worth measuring,
// because when it reaches one the node starts missing its cadence, and a node
// whose emissions drift with load is a node whose timing carries load.
//
// Objects per epoch is likewise arithmetic: cells per epoch times the payload a
// cell carries, divided by the object. What it is not is a rate anyone will
// see, and Envelope says so in the name -- it is a ceiling that assumes every
// cell carries work, and no real epoch does, because cover traffic is the point.
package capacity

import (
	"errors"
	"fmt"
	"time"
)

// PayloadBytesPerCell is the publication payload one wire cell carries.
//
// A cell is 1200 bytes on the wire and 504 of them are the mix plaintext. The
// difference is not overhead to be optimised away: it is the committee
// ciphertext, the sequence and the padding that make every cell the same size.
const PayloadBytesPerCell = 504

// Envelope is the capacity a traffic class and topology imply, before anything
// is measured.
type Envelope struct {
	// CellIntervalMillis is the public cadence from the signed topology.
	CellIntervalMillis uint32
	// Links is how many peers this operator emits to. In a fully connected
	// topology of n operators that is n-1.
	Links int
	// EpochSeconds is how long one epoch stays active.
	EpochSeconds uint64
	// CacheStreams is the operator's raw-cache stream bound.
	CacheStreams int
}

// Validate rejects an envelope that cannot describe a real deployment.
func (envelope Envelope) Validate() error {
	if envelope.CellIntervalMillis < 5 || envelope.CellIntervalMillis > 60_000 {
		return fmt.Errorf("cell interval %d ms is outside the range the topology permits",
			envelope.CellIntervalMillis)
	}
	if envelope.Links < 1 {
		return errors.New("an operator with no links emits nothing")
	}
	if envelope.EpochSeconds == 0 {
		return errors.New("an epoch of zero seconds carries nothing")
	}
	if envelope.CacheStreams < 1 {
		return errors.New("a cache that holds no streams stores nothing")
	}
	return nil
}

// Interval is the cadence as a duration.
func (envelope Envelope) Interval() time.Duration {
	return time.Duration(envelope.CellIntervalMillis) * time.Millisecond
}

// CellsPerSecondPerLink is fixed by the topology, not by the hardware.
func (envelope Envelope) CellsPerSecondPerLink() float64 {
	return 1000 / float64(envelope.CellIntervalMillis)
}

// CellsPerSecondPerOperator counts one direction. An operator both sends and
// receives this many, so the per-cell work it must finish inside one interval
// is one seal and one open per link.
func (envelope Envelope) CellsPerSecondPerOperator() float64 {
	return envelope.CellsPerSecondPerLink() * float64(envelope.Links)
}

// CellsPerEpochPerOperator is the emission budget of one epoch.
func (envelope Envelope) CellsPerEpochPerOperator() uint64 {
	return uint64(envelope.CellsPerSecondPerOperator() * float64(envelope.EpochSeconds))
}

// PayloadBytesPerEpoch is the ceiling on publication bytes an operator's links
// could carry in an epoch if every cell carried work.
//
// No epoch looks like this. Cover traffic is not waste to be minimised, it is
// the mechanism, so the fraction of cells carrying work is a privacy parameter
// rather than an efficiency one. This is the denominator a deployment divides
// by its chosen work fraction, not a throughput.
func (envelope Envelope) PayloadBytesPerEpoch() uint64 {
	return envelope.CellsPerEpochPerOperator() * PayloadBytesPerCell
}

// ObjectsPerEpoch is the same ceiling expressed in objects of a given size.
//
// It ignores coding overhead. RLNC sends more coded fragments than an object
// has source fragments, so the real figure is lower by the coding rate, and a
// deployment that wants a number it can plan with must divide by both that and
// its work fraction.
func (envelope Envelope) ObjectsPerEpoch(objectBytes uint64) (uint64, error) {
	if objectBytes == 0 {
		return 0, errors.New("an object of zero bytes is not an object")
	}
	cellsPerObject := (objectBytes + PayloadBytesPerCell - 1) / PayloadBytesPerCell
	return envelope.CellsPerEpochPerOperator() / cellsPerObject, nil
}

// Cost is the measured price of one per-cell or per-session operation.
type Cost struct {
	Name string `json:"name"`
	// Each is the mean duration of one operation.
	Each time.Duration `json:"each_ns"`
	// Samples is how many operations the mean is over.
	Samples int `json:"samples"`
	// OnThePath records whether this operation is on the production path or is
	// a library capability nothing deployed calls yet. A cost measured for
	// something no command runs is a fact about the code, not about a
	// deployment, and reporting the two the same way would overstate both.
	OnThePath bool `json:"on_the_production_path"`
}

// PerSecond is how many of this operation a single core completes.
func (cost Cost) PerSecond() float64 {
	if cost.Each <= 0 {
		return 0
	}
	return float64(time.Second) / float64(cost.Each)
}

// Headroom is how many times the interval the operation fits into.
//
// One means the node finishes exactly on its deadline and has nothing left for
// scheduling, the kernel, or a second link. Below one it is already late.
func (cost Cost) Headroom(interval time.Duration) float64 {
	if cost.Each <= 0 {
		return 0
	}
	return float64(interval) / float64(cost.Each)
}

// Report is one capacity measurement, as published.
type Report struct {
	// Environment names where the numbers came from. A figure from a shared
	// container is not the same kind of figure as one from a preregistered
	// campaign on dedicated hardware, and the difference has to travel with
	// the number rather than be recoverable from a commit message.
	Environment string   `json:"environment"`
	Envelope    Envelope `json:"envelope"`
	Costs       []Cost   `json:"costs"`
	// Derived carries the arithmetic so a reader does not have to redo it.
	Derived map[string]float64 `json:"derived"`
	// NotEstablished is what this report does not show. It is a required
	// field: a capacity report whose limits are optional is a capacity report
	// that will be quoted without them.
	NotEstablished []string `json:"not_established"`
}

// Validate refuses a report that would be quoted as more than it is.
func (report Report) Validate() error {
	if report.Environment == "" {
		return errors.New("a capacity figure with no environment is not interpretable")
	}
	if err := report.Envelope.Validate(); err != nil {
		return err
	}
	if len(report.Costs) == 0 {
		return errors.New("a report with no measured costs is arithmetic, not a measurement")
	}
	for _, cost := range report.Costs {
		if cost.Each <= 0 || cost.Samples < 1 {
			return fmt.Errorf("cost %q has no measurement behind it", cost.Name)
		}
	}
	if len(report.NotEstablished) == 0 {
		return errors.New("a capacity report must state what it does not establish")
	}
	return nil
}
