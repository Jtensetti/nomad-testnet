package airlock

import (
	"bytes"
	"crypto/rand"
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
	// ErrEpochFull reports an epoch that has no remaining slots.
	ErrEpochFull = errors.New("release epoch has no free slots")
	// ErrDepositConflict reports two different payloads under one deposit ID.
	ErrDepositConflict = errors.New("deposit ID already holds a different payload")
	// ErrSealed reports an operation on an already-sealed epoch.
	ErrSealed = errors.New("release epoch is already sealed")
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
	sealed    bool
}

// New opens the accumulator for one release epoch.
func New(schedule Schedule, committee mix.PublicKey, epoch uint64) (*Airlock, error) {
	if err := schedule.Validate(); err != nil {
		return nil, err
	}
	opens, closes, err := schedule.DepositWindow(epoch)
	if err != nil {
		return nil, err
	}
	return &Airlock{
		schedule: schedule, committee: committee, epoch: epoch,
		opens: opens, closes: closes,
		deposits: make(map[[32]byte][DepositSize]byte, schedule.BatchSize),
	}, nil
}

func (airlock *Airlock) Epoch() uint64 { return airlock.epoch }

// Deposit accepts one client-sealed fragment.
//
// It is idempotent by deposit ID: re-offering the identical payload succeeds
// without consuming a second slot, so a client that cannot tell whether its
// uplink cell arrived can safely resend. Offering a different payload under
// an ID already held is refused rather than overwriting, because whichever
// one an overwrite dropped would be a publication silently lost.
//
// Deposit never triggers a release and never moves a deadline. Filling the
// last slot is not an event.
func (airlock *Airlock) Deposit(id [32]byte, payload [DepositSize]byte, now time.Time) error {
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
		if !bytes.Equal(existing[:], payload[:]) {
			return ErrDepositConflict
		}
		return nil
	}
	if len(airlock.deposits) >= airlock.schedule.BatchSize {
		// Capacity is public and fixed. The alternative -- growing the batch
		// -- would publish the number of real deposits in the batch size
		// itself, so a refused deposit waits for the next epoch instead. The
		// client keeps emitting uplink cover either way, so refusal is not
		// visible on the wire.
		return ErrEpochFull
	}
	airlock.deposits[id] = payload
	return nil
}

// Pending is the number of real deposits held. It is operator-local
// accounting for capacity planning and must never be published, because it
// is exactly the count the fixed batch size exists to hide.
func (airlock *Airlock) Pending() int {
	airlock.mutex.Lock()
	defer airlock.mutex.Unlock()
	return len(airlock.deposits)
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
func (airlock *Airlock) Seal(now time.Time) (*mix.Batch, []mix.WireCell, error) {
	airlock.mutex.Lock()
	defer airlock.mutex.Unlock()
	if airlock.sealed {
		return nil, nil, ErrSealed
	}
	if now.Before(airlock.closes) {
		return nil, nil, fmt.Errorf("%w: epoch %d closes at %s",
			ErrWindowOpen, airlock.epoch, airlock.closes.UTC().Format(time.RFC3339))
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

	// Cover fills the rest. It is a real committee encryption of the reserved
	// empty fragment on the identical path, not a random filler: a filler
	// that is not a valid ciphertext would fail the shuffle proofs, and one
	// that is distinguishable from a real deposit would publish the count.
	for len(columns) < airlock.schedule.BatchSize {
		cover, err := coverColumn(airlock.committee)
		if err != nil {
			return nil, nil, err
		}
		columns = append(columns, cover)
	}

	// Cover is placed by a fresh uniform shuffle rather than appended at the
	// end, where its position would announce how many real deposits preceded
	// it. This is defence in depth: the verifiable shuffle chain that follows
	// permutes the batch again, and the sealed order is seen only by the
	// entry operator, which already knows its own deposits.
	if err := shuffleColumns(columns); err != nil {
		return nil, nil, err
	}

	batch, err := mix.ParseWire(columns)
	if err != nil {
		return nil, nil, fmt.Errorf("sealed batch is not a valid mix batch: %w", err)
	}
	airlock.sealed = true
	return batch, columns, nil
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
	// mix.Encrypt requires at least two columns, so a pair is encrypted and
	// one column taken. Each column is an independent ElGamal encryption, so
	// the discarded one carries no relationship to the kept one.
	empty := EmptyFragment()
	batch, err := mix.Encrypt(committee, []mix.PlainCell{empty, empty})
	if err != nil {
		return mix.WireCell{}, err
	}
	cells, err := batch.MarshalWire()
	if err != nil {
		return mix.WireCell{}, err
	}
	return cells[0], nil
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
