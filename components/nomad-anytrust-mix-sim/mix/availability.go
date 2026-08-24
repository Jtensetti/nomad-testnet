package mix

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Soundness and availability are different accountability problems and this
// package answers them differently.
//
// Soundness is settled by blame.go: a mixer that signs a receipt over a
// transformation whose proof does not verify has produced, with its own key,
// the complete evidence of its own fault. Anyone can re-derive it. There is
// nothing to believe.
//
// Availability cannot be settled that way. A mixer that never sends its round
// signs nothing, so there is no artefact to check. Worse, in an asynchronous
// network no observer can distinguish a mixer that withheld its round from a
// mixer whose packets were dropped, or from its own receiver being partitioned.
// That distinction is not merely unimplemented here; it is not decidable from
// the transcript, and any code claiming otherwise would be claiming a synchrony
// assumption Nomad does not have.
//
// So this file does not prove unavailability. It records it, in a form that is
// checkable, bounded and reversible:
//
//   - A round has a deadline fixed by the public schedule before any batch
//     exists. It is a pure function of the epoch's timetable and the round's
//     position, never of what a batch contains or of who is reading.
//   - Each observer signs its own statement that it had not received the
//     accused mixer's round by that deadline. The statement is bound to one
//     network position: committee, epoch, batch, round, deadline and accused.
//   - A report is a quorum of such statements from distinct certified
//     operators. Below quorum it establishes nothing, which is what stops one
//     operator from evicting a peer it dislikes.
//   - The accused refutes the report by producing its round. A refuted report
//     does not merely evaporate: because every statement in it is individually
//     signed, refutation names exactly which operators asserted something the
//     transcript contradicts.
//
// That last property is the point. The report is honest about being an
// observation rather than a proof, and the cost of a false observation falls on
// whoever signed it.

// Availability fault kinds, distinct from the soundness kinds in blame.go.
const (
	// FaultUnavailable: a quorum of certified operators independently
	// attested that the accused mixer's round had not arrived by the public
	// deadline. This is an observation, not proof of withholding.
	FaultUnavailable = "unavailable"
	// FaultFalseAvailabilityReport: the accused produced the round the report
	// says never arrived, so the observers who signed it asserted something
	// the transcript contradicts. Attributable to those observers.
	FaultFalseAvailabilityReport = "false-availability-report"
)

var (
	// ErrBelowQuorum reports that too few distinct certified operators
	// attested for the report to establish anything.
	ErrBelowQuorum = errors.New("availability report is below the observer quorum")
	// ErrNotRefuted reports that the offered round does not answer the report.
	ErrNotRefuted = errors.New("the offered round does not refute this report")
)

// RoundSchedule is the public timetable a committee fixes when its epoch
// opens. Every field is deployment policy decided before any batch exists, so
// a deadline derived from it cannot encode anything about a batch's contents
// or about who is reading.
type RoundSchedule struct {
	// EpochStart is when the epoch's first batch slot opens, in Unix
	// nanoseconds.
	EpochStart int64
	// BatchInterval is the fixed cadence between batch slots.
	BatchInterval time.Duration
	// RoundBudget is how long one mixer has to return its round.
	RoundBudget time.Duration
}

func (schedule RoundSchedule) validate() error {
	if schedule.EpochStart <= 0 {
		return errors.New("the schedule needs a positive epoch start")
	}
	if schedule.BatchInterval <= 0 || schedule.RoundBudget <= 0 {
		return errors.New("the batch interval and round budget must be positive")
	}
	return nil
}

// Deadline returns when round `round` of the batch in slot `slot` is late.
//
// It takes a slot index rather than a batch because it must not be able to see
// one: a deadline that could vary with batch contents would let the schedule
// itself carry a signal.
func (schedule RoundSchedule) Deadline(slot uint64, round uint32) (int64, error) {
	if err := schedule.validate(); err != nil {
		return 0, err
	}
	slotStart := schedule.EpochStart + int64(slot)*int64(schedule.BatchInterval)
	if slot != 0 && (slotStart-schedule.EpochStart)/int64(schedule.BatchInterval) != int64(slot) {
		return 0, errors.New("the slot index overflows the epoch timetable")
	}
	deadline := slotStart + int64(round+1)*int64(schedule.RoundBudget)
	if deadline <= slotStart {
		return 0, errors.New("the round index overflows the batch slot")
	}
	return deadline, nil
}

// NonReceipt is one operator's signed statement that it had not received the
// accused mixer's round by the round's public deadline.
//
// It carries no batch contents, no reader state and no timing beyond the
// deadline that public policy already fixed.
type NonReceipt struct {
	Context  RoundContext
	Deadline int64
	// Accused is the mixer identity key whose round did not arrive.
	Accused [ed25519.PublicKeySize]byte
	// Observer is the certified operator making the statement.
	Observer  [ed25519.PublicKeySize]byte
	Signature [ed25519.SignatureSize]byte
}

// SignNonReceipt produces one observer's statement. The caller decides when
// the deadline has passed; this function binds the statement to it.
func SignNonReceipt(ctx RoundContext, deadline int64, accused [ed25519.PublicKeySize]byte,
	observer ed25519.PrivateKey) (NonReceipt, error) {
	if err := validateRoundContext(ctx); err != nil {
		return NonReceipt{}, err
	}
	if deadline <= 0 {
		return NonReceipt{}, errors.New("a non-receipt needs the round's public deadline")
	}
	if len(observer) != ed25519.PrivateKeySize {
		return NonReceipt{}, errors.New("an observer identity private key is required")
	}
	observerPublic, ok := observer.Public().(ed25519.PublicKey)
	if !ok || len(observerPublic) != ed25519.PublicKeySize {
		return NonReceipt{}, errors.New("invalid observer identity key")
	}
	statement := NonReceipt{Context: ctx, Deadline: deadline, Accused: accused}
	copy(statement.Observer[:], observerPublic)
	if statement.Observer == statement.Accused {
		return NonReceipt{}, errors.New("an operator cannot report itself unavailable")
	}
	signature := ed25519.Sign(observer, nonReceiptSigningMessage(statement))
	copy(statement.Signature[:], signature)
	return statement, nil
}

func nonReceiptSigningMessage(statement NonReceipt) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-mix-non-receipt-v1"))
	contextDigest := roundContextDigest(statement.Context)
	_, _ = h.Write(contextDigest[:])
	var deadline [8]byte
	binary.BigEndian.PutUint64(deadline[:], uint64(statement.Deadline))
	_, _ = h.Write(deadline[:])
	_, _ = h.Write(statement.Accused[:])
	_, _ = h.Write(statement.Observer[:])
	return h.Sum(nil)
}

// VerifyNonReceipt checks one statement's signature against the key it names.
func VerifyNonReceipt(statement NonReceipt) error {
	if err := validateRoundContext(statement.Context); err != nil {
		return err
	}
	if statement.Deadline <= 0 {
		return errors.New("a non-receipt needs the round's public deadline")
	}
	if statement.Observer == statement.Accused {
		return errors.New("an operator cannot report itself unavailable")
	}
	if !ed25519.Verify(statement.Observer[:], nonReceiptSigningMessage(statement), statement.Signature[:]) {
		return errors.New("the non-receipt does not verify under the observer key it names")
	}
	return nil
}

// AvailabilityReport is a quorum of independent non-receipts about one mixer's
// one round.
type AvailabilityReport struct {
	Context      RoundContext
	Deadline     int64
	Accused      [ed25519.PublicKeySize]byte
	Observations []NonReceipt
}

// VerifyAvailabilityReport establishes that a report is what it claims: a
// quorum of distinct certified operators, none of them the accused, each
// individually signing the same public round position.
//
// quorum is deployment policy. It must exceed the number of operators a
// deployment is willing to assume can collude, because nothing below that can
// distinguish a genuinely absent mixer from a coalition saying so.
func VerifyAvailabilityReport(committee ThresholdCommittee, mixers []ed25519.PublicKey,
	report AvailabilityReport, quorum int) error {
	if quorum <= 0 {
		return errors.New("an availability report needs a positive observer quorum")
	}
	if err := validateRoundContext(report.Context); err != nil {
		return err
	}
	if report.Context.CommitteeID != committee.ID || report.Context.Epoch != committee.Epoch {
		return errors.New("the report is bound to a different committee or epoch")
	}
	if report.Deadline <= 0 {
		return errors.New("the report needs the round's public deadline")
	}
	members := map[string]struct{}{}
	for _, mixer := range mixers {
		members[string(mixer)] = struct{}{}
	}
	if _, member := members[string(report.Accused[:])]; !member {
		return errors.New("the report accuses a key outside the certified committee")
	}

	distinct := map[[ed25519.PublicKeySize]byte]struct{}{}
	for index, statement := range report.Observations {
		if statement.Context != report.Context || statement.Deadline != report.Deadline ||
			statement.Accused != report.Accused {
			return fmt.Errorf("observation %d is about a different round or mixer", index)
		}
		if _, member := members[string(statement.Observer[:])]; !member {
			return fmt.Errorf("observation %d is signed by a key outside the certified committee", index)
		}
		if err := VerifyNonReceipt(statement); err != nil {
			return fmt.Errorf("observation %d: %w", index, err)
		}
		if _, repeated := distinct[statement.Observer]; repeated {
			// Counting a repeated signer twice would let one operator
			// manufacture a quorum by itself.
			return fmt.Errorf("observation %d repeats an observer already counted", index)
		}
		distinct[statement.Observer] = struct{}{}
	}
	if len(distinct) < quorum {
		return fmt.Errorf("%w: %d distinct observers, %d required",
			ErrBelowQuorum, len(distinct), quorum)
	}
	return nil
}

// Refutation is the accused mixer's answer: the round the report says never
// arrived, and the observers whose statements it contradicts.
type Refutation struct {
	Report AvailabilityReport
	// Contradicted are the observers who attested non-receipt of a round the
	// accused can produce. Their statements were wrong; whether they were
	// dishonest or merely partitioned is not decidable here, which is why
	// this is a list of contradicted statements and not a list of liars.
	Contradicted [][ed25519.PublicKeySize]byte
}

// RefuteAvailabilityReport checks the accused mixer's round against the report.
//
// The round must be genuinely the accused mixer's, genuinely sound, and
// genuinely for the round position the report names. Anything less would let a
// mixer answer a report about round 3 with its work from round 1.
func RefuteAvailabilityReport(encryptionKey PublicKey, committee ThresholdCommittee,
	mixers []ed25519.PublicKey, report AvailabilityReport, quorum int,
	round SignedRound) (*Refutation, error) {
	if err := VerifyAvailabilityReport(committee, mixers, report, quorum); err != nil {
		return nil, err
	}
	if round.Receipt.MixerPublic != report.Accused {
		return nil, fmt.Errorf("%w: it was signed by a different mixer", ErrNotRefuted)
	}
	if round.Receipt.Context != report.Context {
		return nil, fmt.Errorf("%w: it is for a different committee, epoch, batch or round", ErrNotRefuted)
	}
	if round.Input == nil || round.Output == nil {
		return nil, fmt.Errorf("%w: it is missing its input or output batch", ErrNotRefuted)
	}
	if err := VerifySignedRound(encryptionKey, round.Input, round.Output,
		round.Proof, round.Receipt); err != nil {
		// An unsound round is not a defence. It is a soundness fault, and
		// blame.go attributes it.
		return nil, fmt.Errorf("%w: %v", ErrNotRefuted, err)
	}
	contradicted := make([][ed25519.PublicKeySize]byte, 0, len(report.Observations))
	for _, statement := range report.Observations {
		contradicted = append(contradicted, statement.Observer)
	}
	return &Refutation{Report: report, Contradicted: contradicted}, nil
}

// AvailabilityFault renders a verified report as a FaultReport, so callers
// handle availability and soundness through one type.
//
// Attributable is deliberately false: a quorum of operators observing that a
// round did not arrive establishes that the round did not arrive at them, not
// that the accused chose to withhold it.
func AvailabilityFault(report AvailabilityReport) FaultReport {
	return FaultReport{
		Kind:         FaultUnavailable,
		Round:        int(report.Context.Round),
		Accused:      append([]byte(nil), report.Accused[:]...),
		Attributable: false,
		Reason: fmt.Sprintf("%d certified operators attested that this mixer's round "+
			"had not arrived by the public deadline, which an asynchronous network "+
			"cannot distinguish from withholding", len(report.Observations)),
	}
}

// RefutedFault renders a refutation as a FaultReport against the observers.
//
// This one is attributable in substance but names several operators rather than
// one, so Accused stays empty and the observers are listed in the reason. A
// caller that needs them individually reads Refutation.Contradicted.
func RefutedFault(refutation Refutation) FaultReport {
	return FaultReport{
		Kind:         FaultFalseAvailabilityReport,
		Round:        int(refutation.Report.Context.Round),
		Attributable: false,
		Reason: fmt.Sprintf("the accused mixer produced a sound round for this position, "+
			"so the %d observers who attested non-receipt asserted something the "+
			"transcript contradicts", len(refutation.Contradicted)),
	}
}
