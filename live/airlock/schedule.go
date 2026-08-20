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
	return nil
}

// EpochAt is the release epoch containing an instant. Instants before genesis
// have no epoch.
func (schedule Schedule) EpochAt(now time.Time) (uint64, error) {
	if err := schedule.Validate(); err != nil {
		return 0, err
	}
	if now.Before(schedule.Genesis) {
		return 0, errors.New("instant precedes the release schedule genesis")
	}
	return uint64(now.Sub(schedule.Genesis) / schedule.Period), nil
}

// DepositWindow is when an epoch accepts deposits: from its opening boundary
// until DepositCutoff before its release.
func (schedule Schedule) DepositWindow(epoch uint64) (time.Time, time.Time, error) {
	if err := schedule.Validate(); err != nil {
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
	return schedule.Genesis.Add(time.Duration(epoch+1) * schedule.Period), nil
}
