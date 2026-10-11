package deposit

import (
	"errors"
	"fmt"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/airlock"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// Ingress is the entry operator's half: it opens uplink cells and hands their
// inner committee ciphertext to the airlock.
//
// It cannot tell work from cover and must not try. The inner layer is
// encrypted to the committee, so only threshold decryption reveals which
// columns were the reserved empty fragment, and that happens after the shuffle
// chain has already destroyed the link to whoever deposited them. An entry
// operator that could distinguish them would be a publisher-to-object mapping
// by itself.
type Ingress struct {
	airlock *airlock.Airlock
}

// ErrNotForThisEpoch reports a cell that authenticated but belongs to an
// airlock epoch that is not open.
var ErrNotForThisEpoch = errors.New("deposit does not belong to the open epoch")

// ErrCellRefused reports a cell that did not open under the session it was
// offered to.
//
// It is a sentinel rather than a bare error because a caller holding more than
// one session for a source needs to tell "not this session" from "this session,
// and the airlock refused it": the first means try the next session, the second
// means stop. Without the distinction a caller must either try only one session
// or risk depositing the same cell twice.
var ErrCellRefused = errors.New("uplink cell refused")

func NewIngress(target *airlock.Airlock) (*Ingress, error) {
	if target == nil {
		return nil, errors.New("airlock is required")
	}
	return &Ingress{airlock: target}, nil
}

// Accept opens one uplink cell from a session and deposits it.
//
// sessionID identifies the uplink session, not the publisher: deposit
// identifiers are derived inside the airlock from (session, sequence) so that
// one depositor can neither name nor squat another's slot. The operator never
// sees a publisher identity here, because nothing in the cell carries one.
//
// A cell that fails authentication is refused without touching the airlock. A
// deposit the airlock silently drops -- a full epoch, an exhausted per-session
// quota -- returns nil, because telling the caller otherwise would turn the
// airlock's occupancy into something a depositor can probe.
func (ingress *Ingress) Accept(session *uplink.Session, sessionID [32]byte,
	cell fabric.Cell, now time.Time) error {
	if session == nil {
		return errors.New("uplink session is required")
	}
	sequence, inner, err := session.Open(cell)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCellRefused, err)
	}
	// A deposit is exactly the uplink's inner layer. Both sizes are compile-time
	// constants, so comparing them at runtime is a check that can never fail;
	// the assignment is what enforces the equality, and stops the build if the
	// two ever part rather than silently truncating a deposit.
	var payload [airlock.DepositSize]byte = inner
	if err := ingress.airlock.Deposit(sessionID, sequence, payload, now); err != nil {
		if errors.Is(err, airlock.ErrWindowClosed) || errors.Is(err, airlock.ErrSealed) {
			return ErrNotForThisEpoch
		}
		return err
	}
	return nil
}
