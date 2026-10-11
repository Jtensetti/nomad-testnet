// Package availability records which certified operators failed to deliver
// their threshold work by a public deadline, and signs that record so peers
// can check it.
//
// The privacy constraint shapes the whole design. An availability report is an
// externally observable artefact, so whatever decides to emit one must be
// public: the deadline comes from the epoch's fixed timetable, the accused set
// is the entire certified committee, and the observation runs on the share
// service's fixed cadence. Nothing here may consult a reader's query, a
// fetch plan, a basin or a reconstruction. If it did, the presence or shape of
// a report would carry private activity out onto the network, which is exactly
// what the fixed schedule exists to prevent.
//
// Two consequences follow, and both are deliberate:
//
//   - Observe always returns a decision for every certified operator, never
//     only for the ones that failed. A caller that emitted only failures would
//     make report volume a function of who was slow, and slowness correlates
//     with load, and load correlates with what people are reading.
//   - A report establishes that work did not arrive at the observers by the
//     deadline. It never claims the operator withheld it. In an asynchronous
//     network those are not distinguishable, and mix.AvailabilityReport carries
//     the refutation path that lets the accused answer.
package availability

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// Delivery reports whether one committee member's threshold work for a batch
// has arrived in a usable state.
//
// Presence is not delivery. An operator that writes an empty file, a truncated
// one, or one whose proof does not verify has produced nothing another operator
// can combine, so it has not delivered.
type Delivery interface {
	Delivered(streamID string, memberIndex uint32) (bool, error)
}

// Observer is one operator's view of its peers at the public deadlines.
type Observer struct {
	// Schedule is the epoch's public timetable. It fixes deadlines before any
	// batch exists.
	Schedule mix.RoundSchedule
	// Committee is the certified committee this epoch.
	Committee mix.ThresholdCommittee
	// Operators is the certified operator set, from the signed topology. Its
	// identity keys are what a report accuses and what a peer verifies.
	Operators []topology.Operator
	// Self is this observer's own operator ID. It is never accused by its own
	// statements.
	Self string
	// Identity signs this observer's statements.
	Identity ed25519.PrivateKey
	// Delivery answers whether a peer's work arrived.
	Delivery Delivery
}

// Judgement is what an observer concluded about one operator at one deadline.
// Observe returns one per certified operator, delivered or not, so that the
// number of judgements never varies with how many operators were late.
type Judgement struct {
	OperatorID  string
	MemberIndex uint32
	Delivered   bool
	// Statement is the signed non-receipt, present only when Delivered is
	// false and the operator is not the observer itself.
	Statement *mix.NonReceipt
}

// Position names the public slot an observation is about.
type Position struct {
	// StreamID identifies the batch on disk.
	StreamID string
	// BatchDigest is the batch's identity, which the statements bind to.
	BatchDigest [32]byte
	// Slot is the batch's index in the epoch's fixed timetable.
	Slot uint64
}

func (observer Observer) validate() error {
	if len(observer.Operators) == 0 {
		return errors.New("an observer needs the certified operator set")
	}
	if observer.Self == "" {
		return errors.New("an observer needs its own operator ID")
	}
	if len(observer.Identity) != ed25519.PrivateKeySize {
		return errors.New("an observer needs its identity private key")
	}
	if observer.Delivery == nil {
		// A nil Delivery would read as "nobody delivered" and turn the
		// observer into an accusation machine. Refuse it rather than default.
		return errors.New("an observer needs a delivery source")
	}
	found := false
	for _, operator := range observer.Operators {
		if operator.ID == observer.Self {
			found = true
			break
		}
	}
	if !found {
		return errors.New("the observer is not in the certified operator set")
	}
	return nil
}

// Observe judges every certified operator at the given slot's public deadline.
//
// It takes the position rather than a clock: the deadline is a property of the
// timetable, and a caller that could pass "now" could make the deadline depend
// on when it happened to run.
func (observer Observer) Observe(position Position) ([]Judgement, error) {
	if err := observer.validate(); err != nil {
		return nil, err
	}
	if position.StreamID == "" || position.BatchDigest == [32]byte{} {
		return nil, errors.New("an observation needs the batch it is about")
	}
	deadline, err := observer.Schedule.Deadline(position.Slot, 0)
	if err != nil {
		return nil, err
	}
	ctx := mix.RoundContext{
		CommitteeID: observer.Committee.ID,
		Epoch:       observer.Committee.Epoch,
		BatchID:     position.BatchDigest,
		// Threshold decryption has one contribution per operator per batch,
		// so there is no round index to vary. Fixing it at zero keeps the
		// context total rather than leaving a field free for a caller to
		// vary per observation.
		Round: 0,
	}

	operators := append([]topology.Operator(nil), observer.Operators...)
	sort.Slice(operators, func(a, b int) bool { return operators[a].Index < operators[b].Index })

	judgements := make([]Judgement, 0, len(operators))
	for _, operator := range operators {
		index := uint32(operator.Index)
		delivered, err := observer.Delivery.Delivered(position.StreamID, index)
		if err != nil {
			return nil, fmt.Errorf("operator %s: %w", operator.ID, err)
		}
		judgement := Judgement{OperatorID: operator.ID, MemberIndex: index, Delivered: delivered}
		if !delivered && operator.ID != observer.Self {
			accused, err := identityKey(operator)
			if err != nil {
				return nil, fmt.Errorf("operator %s: %w", operator.ID, err)
			}
			statement, err := mix.SignNonReceipt(ctx, deadline, accused, observer.Identity)
			if err != nil {
				return nil, fmt.Errorf("operator %s: %w", operator.ID, err)
			}
			judgement.Statement = &statement
		}
		judgements = append(judgements, judgement)
	}
	return judgements, nil
}

func identityKey(operator topology.Operator) ([ed25519.PublicKeySize]byte, error) {
	var key [ed25519.PublicKeySize]byte
	decoded, err := topology.OperatorIdentity(operator)
	if err != nil {
		return key, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return key, errors.New("operator identity key is the wrong size")
	}
	copy(key[:], decoded)
	return key, nil
}

// CertifiedKeys returns the operator identity keys a report may accuse or be
// signed by, in committee-index order.
func CertifiedKeys(operators []topology.Operator) ([]ed25519.PublicKey, error) {
	ordered := append([]topology.Operator(nil), operators...)
	sort.Slice(ordered, func(a, b int) bool { return ordered[a].Index < ordered[b].Index })
	keys := make([]ed25519.PublicKey, 0, len(ordered))
	for _, operator := range ordered {
		key, err := identityKey(operator)
		if err != nil {
			return nil, fmt.Errorf("operator %s: %w", operator.ID, err)
		}
		keys = append(keys, append(ed25519.PublicKey(nil), key[:]...))
	}
	return keys, nil
}

// Assemble groups statements collected from peers into one report per accused
// operator, and returns only the reports that reach quorum.
//
// Statements that do not verify, that name a key outside the certified set, or
// that belong to a different position are dropped rather than failing the
// whole assembly: one operator sending a malformed statement must not be able
// to suppress every report in the batch.
func Assemble(committee mix.ThresholdCommittee, operators []topology.Operator,
	statements []mix.NonReceipt, quorum int) ([]mix.AvailabilityReport, error) {
	if quorum <= 0 {
		return nil, errors.New("assembling reports needs a positive observer quorum")
	}
	keys, err := CertifiedKeys(operators)
	if err != nil {
		return nil, err
	}
	grouped := map[[ed25519.PublicKeySize]byte]*mix.AvailabilityReport{}
	for _, statement := range statements {
		if err := mix.VerifyNonReceipt(statement); err != nil {
			continue
		}
		report, exists := grouped[statement.Accused]
		if !exists {
			report = &mix.AvailabilityReport{
				Context: statement.Context, Deadline: statement.Deadline,
				Accused: statement.Accused,
			}
			grouped[statement.Accused] = report
		}
		if statement.Context != report.Context || statement.Deadline != report.Deadline {
			continue
		}
		report.Observations = append(report.Observations, statement)
	}

	established := make([]mix.AvailabilityReport, 0, len(grouped))
	for _, report := range grouped {
		if err := mix.VerifyAvailabilityReport(committee, keys, *report, quorum); err != nil {
			continue
		}
		established = append(established, *report)
	}
	sort.Slice(established, func(a, b int) bool {
		return string(established[a].Accused[:]) < string(established[b].Accused[:])
	})
	return established, nil
}

// VerifiedPartials answers Delivered by decoding and cryptographically
// verifying the partial an operator wrote, exactly as a peer combining it
// would. A file that does not verify is not a delivery.
//
// Decode and Verify are supplied by the caller rather than reached for here.
// That is not indirection for its own sake: live/batch, which owns the partial
// format, imports nomad-local-reconstruction, and an availability observer
// that could reach object reconstruction would be one edge away from being
// able to vary its reports with what a reader wanted. Taking two functions
// keeps this package's transitive graph down to mix and topology, which CI
// enforces.
type VerifiedPartials struct {
	Directory string
	// Decode parses one partial file. An error means the operator wrote
	// something unusable, which is a non-delivery, not a failure here.
	Decode func([]byte) (*mix.PartialDecryption, error)
	// Verify checks a decoded partial against the batch.
	Verify func(*mix.PartialDecryption) error
}

func (partials VerifiedPartials) Delivered(streamID string, memberIndex uint32) (bool, error) {
	if partials.Directory == "" {
		return false, errors.New("a partials directory is required")
	}
	if partials.Decode == nil || partials.Verify == nil {
		return false, errors.New("a partial decoder and verifier are required")
	}
	path := filepath.Join(partials.Directory, fmt.Sprintf("%s-%02d.partial.json", streamID, memberIndex))
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	partial, err := partials.Decode(encoded)
	if err != nil || partial == nil {
		// Undecodable is not an error for the observer: it is a
		// non-delivery by the operator that wrote it.
		return false, nil
	}
	if partial.MemberIndex != memberIndex {
		return false, nil
	}
	if err := partials.Verify(partial); err != nil {
		return false, nil
	}
	return true, nil
}

// SlotFor returns the timetable slot a batch belongs to. It is a pure function
// of the public schedule and the batch's opening time, which the descriptor
// carries; it never sees the batch's contents.
func (observer Observer) SlotFor(opened time.Time) (uint64, error) {
	if observer.Schedule.BatchInterval <= 0 || observer.Schedule.EpochStart <= 0 {
		return 0, errors.New("the schedule is not configured")
	}
	offset := opened.UnixNano() - observer.Schedule.EpochStart
	if offset < 0 {
		return 0, errors.New("the batch opened before the epoch did")
	}
	return uint64(offset / int64(observer.Schedule.BatchInterval)), nil
}
