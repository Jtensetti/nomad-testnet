package epoch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const retirementDirectory = "retirements"

// DecodeErasureStatement strictly decodes one signed erasure statement.
func DecodeErasureStatement(encoded []byte) (ErasureStatement, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return ErasureStatement{}, errors.New("erasure statement is empty or too large")
	}
	var statement ErasureStatement
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&statement); err != nil {
		return ErasureStatement{}, fmt.Errorf("decode erasure statement: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErasureStatement{}, errors.New("trailing erasure statement data")
	}
	return statement, nil
}

func (chain *Chain) retirementPath(epochNumber uint64, operatorID string) string {
	return filepath.Join(chain.root, retirementDirectory, fmt.Sprintf("%020d-%s.erasure.json", epochNumber, operatorID))
}

// RecordErasureStatement is the durable completion acknowledgement for one
// operator's retirement work. The statement is accepted only if it verifies
// against the exact stored epoch and that epoch was RETIRED at ErasedAt.
func (chain *Chain) RecordErasureStatement(statement ErasureStatement, operatorID string) error {
	if operatorID == "" || statement.OperatorID != operatorID {
		return errors.New("erasure statement does not belong to the local operator")
	}
	chain.mu.Lock()
	defer chain.mu.Unlock()
	lock, err := acquireChainLock(chain.root)
	if err != nil {
		return err
	}
	defer func() { _ = lock.release() }()
	if err := chain.refreshLocked(); err != nil {
		return err
	}
	if chain.halted {
		return ErrHalted
	}
	retired, found := chain.epochLocked(statement.Epoch)
	if !found {
		return fmt.Errorf("epoch %d is not stored", statement.Epoch)
	}
	if _, member := operatorByID(retired.Topology, operatorID); !member {
		return fmt.Errorf("operator %q did not hold material for epoch %d", operatorID, statement.Epoch)
	}
	if err := VerifyErasureStatement(statement, retired); err != nil {
		return err
	}
	erasedAt, err := time.Parse(time.RFC3339, statement.ErasedAt)
	if err != nil {
		return errors.New("erasure statement has invalid erased_at")
	}
	state, err := chain.stateOfLocked(statement.Epoch, erasedAt)
	if err != nil {
		return err
	}
	if state != StateRetired {
		return fmt.Errorf("epoch %d was %s at erasure time, not RETIRED", statement.Epoch, state)
	}
	encoded, err := EncodeErasureStatement(statement)
	if err != nil {
		return err
	}
	directory := filepath.Join(chain.root, retirementDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	path := chain.retirementPath(statement.Epoch, operatorID)
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, encoded) {
			return errors.New("conflicting erasure acknowledgement for epoch")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeNewFile(path, encoded, 0o600); err != nil {
		return err
	}
	return syncDir(directory)
}

// ErasureRecorded reports whether a member operator has a valid, durable
// erasure acknowledgement for the epoch. An operator that was not a member
// had no private epoch material and therefore has nothing to acknowledge.
func (chain *Chain) ErasureRecorded(epochNumber uint64, operatorID string) (bool, error) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	lock, err := acquireChainLock(chain.root)
	if err != nil {
		return false, err
	}
	defer func() { _ = lock.release() }()
	if err := chain.refreshLocked(); err != nil {
		return false, err
	}
	retired, found := chain.epochLocked(epochNumber)
	if !found {
		return false, fmt.Errorf("epoch %d is not stored", epochNumber)
	}
	if _, member := operatorByID(retired.Topology, operatorID); !member {
		return true, nil
	}
	return chain.erasureRecordedLocked(epochNumber, operatorID)
}

func (chain *Chain) erasureRecordedLocked(epochNumber uint64, operatorID string) (bool, error) {
	retired, found := chain.epochLocked(epochNumber)
	if !found {
		return false, fmt.Errorf("epoch %d is not stored", epochNumber)
	}
	encoded, err := os.ReadFile(chain.retirementPath(epochNumber, operatorID))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	statement, err := DecodeErasureStatement(encoded)
	if err != nil {
		return false, err
	}
	if statement.OperatorID != operatorID {
		return false, errors.New("stored erasure acknowledgement belongs to another operator")
	}
	if err := VerifyErasureStatement(statement, retired); err != nil {
		return false, err
	}
	return true, nil
}

func (chain *Chain) epochLocked(epochNumber uint64) (Verified, bool) {
	for _, stored := range chain.epochs {
		if stored.Epoch == epochNumber {
			return stored, true
		}
	}
	return Verified{}, false
}

// PlanAtForOperator is the production lifecycle planner. Before it plans any
// future ceremony work it returns the oldest RETIRED epoch in which this
// operator was a member and for which it lacks a durable erasure statement.
func (chain *Chain) PlanAtForOperator(now time.Time, policy Policy, operatorID string) (Plan, error) {
	if operatorID == "" {
		return Plan{}, errors.New("operator ID is required")
	}
	if err := policy.validate(); err != nil {
		return Plan{}, err
	}
	chain.mu.Lock()
	defer chain.mu.Unlock()
	lock, err := acquireChainLock(chain.root)
	if err != nil {
		return Plan{}, err
	}
	defer func() { _ = lock.release() }()
	if err := chain.refreshLocked(); err != nil {
		return Plan{}, err
	}
	if chain.halted {
		return Plan{Action: ActionHalted, Reason: "chain halted on recorded equivocation"}, nil
	}
	for index, stored := range chain.epochs {
		if _, member := operatorByID(stored.Topology, operatorID); !member {
			continue
		}
		state, err := chain.stateOfLocked(stored.Epoch, now)
		if err != nil {
			return Plan{}, err
		}
		if state != StateRetired {
			continue
		}
		recorded, err := chain.erasureRecordedLocked(stored.Epoch, operatorID)
		if err != nil {
			return Plan{}, fmt.Errorf("verify retirement acknowledgement for epoch %d: %w", stored.Epoch, err)
		}
		if recorded {
			continue
		}
		due := stored.RetireAt
		if index+1 < len(chain.epochs) {
			successor := chain.epochs[index+1]
			if successor.Descriptor.Transition == TransitionEmergency && successor.ActivateAt.Before(due) {
				due = successor.ActivateAt
			}
		}
		return Plan{
			Action: ActionRetire, Epoch: stored.Epoch, DueAt: due,
			Reason: "retired epoch has no durable local erasure acknowledgement",
		}, nil
	}
	return chain.planAtLocked(now, policy), nil
}
