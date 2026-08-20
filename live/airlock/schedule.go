// Package airlock is the publication deposit boundary: client-sealed
// fragments enter, a verifiable shuffle chain runs, threshold decryption
// releases plaintexts, and no single operator can link an entering
// ciphertext to a released fragment.
//
// The boundary exists because publishing is private activity. Everything an
// observer can see about it -- when a batch closes, how large it is, when it
// is released, how many fragments come out -- is fixed by public schedule
// parameters, never by what is in the queue. Two rules carry most of that:
//
// A release epoch's timing is a pure function of public parameters. There is
// no API on this package by which a full queue closes a batch sooner or an
// empty one closes it later, and Seal refuses to run before the scheduled
// time even when the batch filled in the first second.
//
// A release epoch's size is fixed. Every batch mixes exactly BatchSize slots,
// padded with cover deposits that are real committee encryptions of the
// reserved empty fragment, so the number of slots -- and the number of
// plaintexts leaving threshold decryption -- says nothing about how many real
// publications there were. Cover is discarded only after decryption, by a
// party that already holds threshold authority.
package airlock

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// Schedule is the public release schedule. Every field is deployment policy
// carried in the signed epoch descriptor. Nothing here may be derived from
// queue depth, publication content, or any other private state.
type Schedule struct {
	// Genesis is the boundary of release epoch 0.
	Genesis time.Time
	// Period is the length of one release epoch.
	Period time.Duration
	// DepositCutoff is how long before the release boundary the deposit
	// window closes, leaving time for the shuffle chain and decryption.
	DepositCutoff time.Duration
	// BatchSize is the fixed number of slots mixed in every release epoch,
	// real deposits and cover together.
	BatchSize int
	// MaxDepositsPerSession bounds how many slots one uplink session may
	// hold in an epoch. Without a per-session bound, one client fills the
	// whole batch with cheap encryptions and denies the epoch to everyone
	// else at no cost. It does not solve Sybil -- an attacker with many
	// authenticated sessions still competes for slots -- which is an
	// admission question (G-05..G-09), not one this boundary can answer.
	MaxDepositsPerSession int
}

// ErrScheduleInvalid reports a schedule that could not be used as public
// policy.
var ErrScheduleInvalid = errors.New("invalid release schedule")

func (schedule Schedule) Validate() error {
	if schedule.Genesis.IsZero() {
		return fmt.Errorf("%w: genesis is required", ErrScheduleInvalid)
	}
	if schedule.Period <= 0 {
		return fmt.Errorf("%w: period must be positive", ErrScheduleInvalid)
	}
	if schedule.DepositCutoff <= 0 || schedule.DepositCutoff >= schedule.Period {
		return fmt.Errorf("%w: deposit cutoff must fall inside the period", ErrScheduleInvalid)
	}
	// A mix batch needs at least two columns, and a batch of two is a
	// two-element anonymity set. The floor is a protocol minimum, not a
	// recommendation; deployments carry a far larger BatchSize.
	if schedule.BatchSize < 2 {
		return fmt.Errorf("%w: batch size must be at least 2", ErrScheduleInvalid)
	}
	if schedule.MaxDepositsPerSession < 1 || schedule.MaxDepositsPerSession > schedule.BatchSize {
		return fmt.Errorf("%w: per-session deposit bound must be between 1 and the batch size",
			ErrScheduleInvalid)
	}
	return nil
}

// ErrEpochOutOfRange reports an epoch whose boundaries are not representable.
var ErrEpochOutOfRange = errors.New("release epoch is outside the representable range")

// MaxEpoch is the highest epoch whose release boundary can be computed
// without overflowing a time.Duration.
//
// Without this bound, time.Duration(epoch) * Period silently wrapped: epoch
// 20,000,000 on a ten-minute period produced a deposit window in 1821, so New
// accepted it and the resulting airlock sealed immediately because its window
// had "closed" two centuries ago -- an instant-seal primitive for anyone able
// to influence the epoch number, and a direct contradiction of release timing
// being a pure function of public parameters.
func (schedule Schedule) MaxEpoch() uint64 {
	if schedule.Period <= 0 {
		return 0
	}
	// epoch+1 is multiplied for ReleaseAt, so the bound leaves room for it.
	return uint64(math.MaxInt64)/uint64(schedule.Period) - 1
}

func (schedule Schedule) checkEpoch(epoch uint64) error {
	if epoch > schedule.MaxEpoch() {
		return fmt.Errorf("%w: %d exceeds %d for a period of %s",
			ErrEpochOutOfRange, epoch, schedule.MaxEpoch(), schedule.Period)
	}
	return nil
}

// EpochAt is the release epoch containing an instant. Instants before genesis,
// and instants too far beyond it to be represented, have no epoch.
func (schedule Schedule) EpochAt(now time.Time) (uint64, error) {
	if err := schedule.Validate(); err != nil {
		return 0, err
	}
	if now.Before(schedule.Genesis) {
		return 0, errors.New("instant precedes the release schedule genesis")
	}
	// Sub saturates at the Duration limits rather than reporting overflow, so
	// a saturated result is rejected instead of being returned as an epoch
	// whose own DepositWindow would disagree with it.
	elapsed := now.Sub(schedule.Genesis)
	if elapsed == math.MaxInt64 {
		return 0, fmt.Errorf("%w: instant is beyond the representable range",
			ErrEpochOutOfRange)
	}
	epoch := uint64(elapsed / schedule.Period)
	if err := schedule.checkEpoch(epoch); err != nil {
		return 0, err
	}
	return epoch, nil
}

// DepositWindow is when an epoch accepts deposits: from its opening boundary
// until DepositCutoff before its release.
func (schedule Schedule) DepositWindow(epoch uint64) (time.Time, time.Time, error) {
	if err := schedule.Validate(); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if err := schedule.checkEpoch(epoch); err != nil {
		return time.Time{}, time.Time{}, err
	}
	opens := schedule.Genesis.Add(time.Duration(epoch) * schedule.Period)
	return opens, opens.Add(schedule.Period - schedule.DepositCutoff), nil
}

// ReleaseAt is when an epoch's plaintexts become public.
func (schedule Schedule) ReleaseAt(epoch uint64) (time.Time, error) {
	if err := schedule.Validate(); err != nil {
		return time.Time{}, err
	}
	if err := schedule.checkEpoch(epoch); err != nil {
		return time.Time{}, err
	}
	return schedule.Genesis.Add(time.Duration(epoch+1) * schedule.Period), nil
}
