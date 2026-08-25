package airlock

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

// DepositSize is one client-sealed committee ciphertext: exactly one column
// of a mix batch, and exactly the inner layer of an uplink cell.
//
// It is derived from the mix parameters rather than imported from live/hop,
// which would be the natural place to get it: hop reaches the transport, and
// this package must have no path to a socket. The equality with
// hop.CiphertextSize is asserted in the tests, where an import costs nothing.
const DepositSize = mix.ChunkCount * 2 * 32

var (
	// ErrWindowClosed reports a deposit offered outside its epoch's window.
	ErrWindowClosed = errors.New("deposit window is closed for this epoch")
	// ErrWindowOpen reports an attempt to seal before the scheduled time.
	ErrWindowOpen = errors.New("deposit window has not closed yet")
	// ErrDepositConflict reports two different payloads under one deposit ID.
	ErrDepositConflict = errors.New("deposit ID already holds a different payload")
	// ErrSealed reports an operation on an already-sealed epoch.
	ErrSealed = errors.New("release epoch is already sealed")
	// ErrDepositMalformed reports a payload that is not a mix batch column.
	ErrDepositMalformed = errors.New("deposit is not a well-formed committee ciphertext")
)

// Airlock accumulates one release epoch's deposits at one entry operator.
//
// It is deliberately incapable of releasing anything: it produces a batch to
// be mixed, and the mixing and threshold decryption happen elsewhere, under
// authority this type does not hold. An entry operator that accumulates
// deposits can therefore not also open them.
type Airlock struct {
	mutex     sync.Mutex
	schedule  Schedule
	committee mix.PublicKey
	epoch     uint64
	opens     time.Time
	closes    time.Time
	deposits  map[[32]byte][DepositSize]byte
	sessions  map[[32]byte]int
	cover     []mix.WireCell
	sealed    bool

	// Operator-local drop accounting. It never reaches a depositor and must
	// never be published: it is a count of how much publishing happened.
	droppedFull    int
	droppedSession int
}

// New opens the accumulator for one release epoch.
//
// It takes the certified committee rather than a bare public key, so the key
// that encrypts cover is by construction the key the shuffle chain and the
// threshold decryption use. Taking a bare key meant an unvalidated one was
// accepted: an all-zero key decodes to a point of order 4, which turns cover
// into a four-way-masked plaintext that anybody recovers with no shares at
// all, and any mismatch between the operator's configuration and the
// certified committee was discovered only at release, after the window had
// closed and every deposit was unrecoverable.
//
// All BatchSize cover columns are generated here, before the window opens.
// Generating them in Seal made its runtime linear in the number of *empty*
// slots -- 2.6 seconds at zero real deposits against 0.014 at a full batch --
// so the release instant read out publication volume, and a concurrent
// depositor could read the same signal by timing how long its own call
// blocked on the lock. The cost is now paid once, at a public time, and is
// identical whatever anybody publishes.
func New(schedule Schedule, committee mix.ThresholdCommittee, epoch uint64) (*Airlock, error) {
	if err := schedule.Validate(); err != nil {
		return nil, err
	}
	if err := mix.ValidateThresholdCommittee(committee); err != nil {
		return nil, fmt.Errorf("airlock committee is not certified: %w", err)
	}
	opens, closes, err := schedule.DepositWindow(epoch)
	if err != nil {
		return nil, err
	}
	cover := make([]mix.WireCell, 0, schedule.BatchSize)
	for index := 0; index < schedule.BatchSize; index++ {
		column, err := coverColumn(committee.PublicKey)
		if err != nil {
			return nil, err
		}
		cover = append(cover, column)
	}
	return &Airlock{
		schedule: schedule, committee: committee.PublicKey, epoch: epoch,
		opens: opens, closes: closes,
		deposits: make(map[[32]byte][DepositSize]byte, schedule.BatchSize),
		sessions: make(map[[32]byte]int, schedule.BatchSize),
		cover:    cover,
	}, nil
}

func (airlock *Airlock) Epoch() uint64 { return airlock.epoch }

// DepositID derives the slot name for one uplink session's sequence number.
//
// The ID is derived here rather than taken from the caller. When callers named
// their own slots, the 32-byte namespace was unauthenticated: anyone could
// probe whether an ID was held -- which, for IDs derived from content or from
// a publisher, is a "did X publish this epoch?" oracle -- and could
// permanently block a publisher by squatting its ID, since a conflicting
// payload is refused by design and there is no override.
//
// session is an opaque per-client value the entry operator holds from the
// uplink key agreement; it is never the session key itself. Deriving from it
// means one depositor cannot name another's slot at all.
func DepositID(session [32]byte, sequence uint64) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-airlock-deposit-id-v1"))
	_, _ = h.Write(session[:])
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], sequence)
	_, _ = h.Write(counter[:])
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

// Deposit accepts one client-sealed fragment for an uplink session's sequence
// number.
//
// It is idempotent: re-offering the identical payload for the same sequence
// succeeds without consuming a second slot, so a client that cannot tell
// whether its uplink cell arrived -- and it cannot, because the uplink
// carries no acknowledgement that would distinguish work from cover -- can
// safely resend. A different payload for a sequence already held is refused
// rather than overwriting, because whichever one an overwrite dropped would
// be a publication silently lost. That refusal is safe to report: with
// derived IDs a caller can only collide with its own earlier deposit.
//
// A full epoch is NOT reported. Returning a distinguishable "epoch full"
// told any depositor the exact number of real deposits in the batch, which is
// the one number the fixed batch size exists to hide, and probing for it
// consumed every remaining slot. The deposit is dropped and counted
// operator-locally instead: losing work is preferable to emitting a
// private-dependent signal, and the client keeps emitting uplink cover either
// way, so nothing on the wire changes.
//
// Deposit never triggers a release and never moves a deadline. Filling the
// last slot is not an event.
func (airlock *Airlock) Deposit(session [32]byte, sequence uint64,
	payload [DepositSize]byte, now time.Time) error {
	id := DepositID(session, sequence)
	airlock.mutex.Lock()
	defer airlock.mutex.Unlock()
	if airlock.sealed {
		return ErrSealed
	}
	if now.Before(airlock.opens) || !now.Before(airlock.closes) {
		return fmt.Errorf("%w: epoch %d accepts deposits in [%s, %s)",
			ErrWindowClosed, airlock.epoch,
			airlock.opens.UTC().Format(time.RFC3339), airlock.closes.UTC().Format(time.RFC3339))
	}
	if existing, held := airlock.deposits[id]; held {
		// Constant time: this is the one comparison in the package whose
		// operands are private publication material, and a byte-at-a-time
		// early exit leaks a prefix of it through timing.
		if subtle.ConstantTimeCompare(existing[:], payload[:]) != 1 {
			return ErrDepositConflict
		}
		return nil
	}
	// Per-session capacity is checked before batch capacity, and both are
	// silent: neither may tell a depositor anything about the epoch's
	// occupancy. Capacity is public and fixed; growing the batch would
	// publish the real-deposit count in the batch size itself.
	if airlock.sessions[session] >= airlock.schedule.MaxDepositsPerSession {
		airlock.droppedSession++
		return nil
	}
	if len(airlock.deposits) >= airlock.schedule.BatchSize {
		airlock.droppedFull++
		return nil
	}
	// A payload whose points do not decode is accepted here and kills Seal
	// for the whole epoch, deterministically and forever: one malformed
	// deposit censors every other publisher, and Seal failing is itself an
	// externally observable event caused entirely by deposit content. Roughly
	// half of all random 32-byte strings are not valid curve points, so this
	// costs an attacker nothing to produce. It is refused before it takes a
	// slot.
	if err := airlock.validatePayload(payload); err != nil {
		return fmt.Errorf("%w: %v", ErrDepositMalformed, err)
	}
	airlock.deposits[id] = payload
	airlock.sessions[session]++
	return nil
}

// validatePayload checks that a deposit decodes as one mix batch column of
// usable points. It is stricter than "does it parse": a column of identity or
// small-order points parses fine and is exactly what an attacker submits to
// occupy a slot with something that cannot decrypt.
func (airlock *Airlock) validatePayload(payload [DepositSize]byte) error {
	var column mix.WireCell
	copy(column[:DepositSize], payload[:])
	return mix.ValidateCiphertextColumn(column)
}

// Pending is the number of real deposits held. It is operator-local
// accounting for capacity planning and must never be published, because it
// is exactly the count the fixed batch size exists to hide.
func (airlock *Airlock) Pending() int {
	airlock.mutex.Lock()
	defer airlock.mutex.Unlock()
	return len(airlock.deposits)
}

// Dropped reports deposits refused for want of capacity, split by cause. Like
// Pending it is operator-local and must never reach a depositor or a
// published record.
func (airlock *Airlock) Dropped() (batchFull int, sessionQuota int) {
	airlock.mutex.Lock()
	defer airlock.mutex.Unlock()
	return airlock.droppedFull, airlock.droppedSession
}

// Sealed reports whether this epoch's batch has been produced.
func (airlock *Airlock) Sealed() bool {
	airlock.mutex.Lock()
	defer airlock.mutex.Unlock()
	return airlock.sealed
}

// Seal closes the epoch at its scheduled time and returns the batch to mix,
// always of exactly BatchSize columns.
//
// It refuses to run early. A batch that filled in the first second of its
// window still waits for the boundary, because closing early is a signal that
// the batch was full, and a batch being full is a fact about how much
// publishing happened.
func (airlock *Airlock) Seal(now time.Time) (Sealed, error) {
	airlock.mutex.Lock()
	defer airlock.mutex.Unlock()
	if airlock.sealed {
		return Sealed{}, ErrSealed
	}
	if now.Before(airlock.closes) {
		return Sealed{}, fmt.Errorf("%w: epoch %d closes at %s",
			ErrWindowOpen, airlock.epoch, airlock.closes.UTC().Format(time.RFC3339))
	}
	// Sealing is also bounded above. Without an upper bound any instant at or
	// after the cutoff sealed, so a late or replayed release was invisible
	// here; the window between the cutoff and the release exists precisely
	// because the chain and the decryption have to fit inside it.
	release, err := airlock.schedule.ReleaseAt(airlock.epoch)
	if err != nil {
		return Sealed{}, err
	}
	if !now.Before(release) {
		return Sealed{}, fmt.Errorf("%w: epoch %d released at %s",
			ErrWindowClosed, airlock.epoch, release.UTC().Format(time.RFC3339))
	}

	// Ordered by deposit ID rather than by arrival, so the entry operator's
	// view of arrival order is not carried into the batch at all. The random
	// placement below would already hide it; removing it here as well means
	// the batch never holds arrival order even momentarily.
	ids := make([][32]byte, 0, len(airlock.deposits))
	for id := range airlock.deposits {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })

	columns := make([]mix.WireCell, 0, airlock.schedule.BatchSize)
	for _, id := range ids {
		payload := airlock.deposits[id]
		var column mix.WireCell
		copy(column[:DepositSize], payload[:])
		columns = append(columns, column)
	}

	// Cover fills the rest, from the set generated before the window opened.
	// It is a real committee encryption of the reserved empty fragment, not a
	// random filler: a filler that is not a valid ciphertext would fail the
	// shuffle proofs, and one distinguishable from a real deposit would
	// publish the count.
	for len(columns) < airlock.schedule.BatchSize {
		columns = append(columns, airlock.cover[len(columns)])
	}

	// Cover is placed by a fresh uniform shuffle rather than appended at the
	// end, where its position would announce how many real deposits preceded
	// it. This is defence in depth: the verifiable shuffle chain that follows
	// permutes the batch again, and the sealed order is seen only by the
	// entry operator, which already knows its own deposits.
	if err := shuffleColumns(columns); err != nil {
		return Sealed{}, err
	}

	batch, err := mix.ParseWire(columns)
	if err != nil {
		// Deposits are validated on arrival, so this is unreachable for
		// deposit content; it stays as a hard failure rather than a warning.
		return Sealed{}, fmt.Errorf("sealed batch is not a valid mix batch: %w", err)
	}

	// Re-derive the wire form from the parsed batch so every column, real and
	// cover alike, gets its padding from one code path.
	//
	// A mix.WireCell is 1200 bytes and a deposit is 1152. Copying a deposit
	// into a zero-valued cell left bytes 1152..1200 zero, while cover came
	// through MarshalWire, which fills them from crypto/rand. That was a
	// one-line classifier: it recovered not just the count of real deposits
	// but exactly which columns were real, with no decryption at all, which
	// is the opposite of what the fixed batch size exists to achieve.
	columns, err = batch.MarshalWire()
	if err != nil {
		return Sealed{}, err
	}

	// The digest commits the chain to this epoch's batch. Without it a
	// verifier has nothing that says which release epoch a chain belongs to,
	// and a whole chain replays from one epoch into another.
	digest, err := batch.Digest()
	if err != nil {
		return Sealed{}, err
	}
	airlock.sealed = true
	return Sealed{
		ReleaseEpoch: airlock.epoch,
		Digest:       digest,
		Columns:      columns,
		batch:        batch,
	}, nil
}

// EmptyFragment is the reserved plaintext that carries no publication. It is
// the same value uplink cover carries, so cover generated by a client and
// cover generated by an entry operator are the same thing after decryption.
func EmptyFragment() mix.PlainCell { return mix.PlainCell{} }

// IsCover reports the reserved empty fragment. Only a party that has
// completed threshold decryption can evaluate it.
func IsCover(cell mix.PlainCell) bool {
	for _, value := range cell {
		if value != 0 {
			return false
		}
	}
	return true
}

func coverColumn(committee mix.PublicKey) (mix.WireCell, error) {
	// One cover column is one ElGamal encryption, so it uses the single-cell
	// path. This used to encrypt a two-column batch and discard a column,
	// because mix.Encrypt refuses fewer than two -- correctly, since a shuffle
	// of one element is the identity, but that is a property of a mix input
	// and a cover column is not one.
	//
	// It ran once per cover column, up to the batch size, so it was the larger
	// consumer of the discarded work than the publisher's seal was. Both now
	// use mix.EncryptCell, which produces exactly the wire form MarshalWire
	// produces for one column.
	return mix.EncryptCell(committee, EmptyFragment())
}

// shuffleColumns permutes in place with a uniform Fisher-Yates draw from the
// system CSPRNG. A failure to read randomness is an error, never a fallback
// to a weaker source.
func shuffleColumns(columns []mix.WireCell) error {
	for index := len(columns) - 1; index > 0; index-- {
		position, err := randomBelow(index + 1)
		if err != nil {
			return err
		}
		columns[index], columns[position] = columns[position], columns[index]
	}
	return nil
}

func randomBelow(bound int) (int, error) {
	if bound <= 0 {
		return 0, errors.New("random bound must be positive")
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(bound)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}
