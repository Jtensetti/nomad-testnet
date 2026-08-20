package epoch

import (
	"errors"
	"fmt"
	"time"
)

// Action is what the lifecycle requires of an operator at a given instant.
type Action int

const (
	// ActionIdle means nothing is due.
	ActionIdle Action = iota
	// ActionPrepareNext means the ceremony for the next epoch should begin.
	ActionPrepareNext
	// ActionAwaitActivation means the successor is assembled and waiting for
	// its public boundary.
	ActionAwaitActivation
	// ActionRetire means the active epoch has reached its boundary and its
	// private material must be erased.
	ActionRetire
	// ActionEscalate means repeated ceremony failures have exhausted the
	// public retry ladder and a membership transition is required.
	ActionEscalate
	// ActionHalted means the chain observed equivocation and does nothing
	// further without authorized intervention.
	ActionHalted
)

func (a Action) String() string {
	switch a {
	case ActionIdle:
		return "IDLE"
	case ActionPrepareNext:
		return "PREPARE_NEXT"
	case ActionAwaitActivation:
		return "AWAIT_ACTIVATION"
	case ActionRetire:
		return "RETIRE"
	case ActionEscalate:
		return "ESCALATE"
	case ActionHalted:
		return "HALTED"
	default:
		return "UNKNOWN"
	}
}

// Policy is the public rotation configuration. Every field is deployment
// policy published with the network; none of it is derived from user
// behavior, queue depth, publication state or reader activity.
type Policy struct {
	// PrepareLead is how long before the active epoch's retirement the
	// successor ceremony begins.
	PrepareLead time.Duration
	// RetryOffsets are the additional public offsets, measured from the
	// first preparation instant, at which a failed ceremony is retried with
	// a fresh session and the same membership.
	RetryOffsets []time.Duration
	// EscalateAfter is the public offset, measured from the first
	// preparation instant, at which an absent successor stops being a retry
	// case and becomes a membership transition. It must fall after the last
	// retry and before the retirement boundary, so the escalation has time
	// to complete while the outgoing epoch is still serving.
	EscalateAfter time.Duration
}

// DefaultPolicy prepares a successor a quarter of a day ahead and retries
// twice before escalating, matching docs/EPOCH_LIFECYCLE.md.
func DefaultPolicy() Policy {
	return Policy{
		PrepareLead:   6 * time.Hour,
		RetryOffsets:  []time.Duration{time.Hour, 2 * time.Hour},
		EscalateAfter: 3 * time.Hour,
	}
}

func (policy Policy) validate() error {
	if policy.PrepareLead <= 0 {
		return errors.New("prepare lead must be positive")
	}
	for index, offset := range policy.RetryOffsets {
		if offset <= 0 {
			return fmt.Errorf("retry offset %d must be positive", index)
		}
		if offset >= policy.PrepareLead {
			return fmt.Errorf("retry offset %d must fall inside the preparation lead", index)
		}
		if index > 0 && offset <= policy.RetryOffsets[index-1] {
			return errors.New("retry offsets must increase")
		}
	}
	if policy.EscalateAfter <= 0 || policy.EscalateAfter >= policy.PrepareLead {
		return errors.New("escalation offset must fall inside the preparation lead")
	}
	if len(policy.RetryOffsets) > 0 && policy.EscalateAfter <= policy.RetryOffsets[len(policy.RetryOffsets)-1] {
		return errors.New("escalation must follow the last retry")
	}
	return nil
}

// Plan is the lifecycle instruction for one instant.
type Plan struct {
	Action Action
	// Epoch is the epoch the action concerns: the successor for
	// PREPARE_NEXT and AWAIT_ACTIVATION, the outgoing epoch for RETIRE.
	Epoch uint64
	// Attempt counts ceremony attempts for a successor, starting at one.
	Attempt int
	// DueAt is the public instant the action became due.
	DueAt time.Time
	// Reason is a human-readable explanation for operator logs. It contains
	// only public schedule facts.
	Reason string
}

// PlanAt reports what the lifecycle requires at the given instant.
//
// It is a pure function of the persisted chain, the supplied clock and the
// public policy. It has no parameter through which private state could
// enter, which is what makes rotation timing independent of user behavior:
// a publication, a query or an idle client all produce the same plan.
func (chain *Chain) PlanAt(now time.Time, policy Policy) (Plan, error) {
	if err := policy.validate(); err != nil {
		return Plan{}, err
	}
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.halted {
		return Plan{Action: ActionHalted, Reason: "chain halted on recorded equivocation"}, nil
	}
	if len(chain.epochs) == 0 {
		return Plan{Action: ActionIdle, Reason: "no genesis epoch yet"}, nil
	}
	tip := chain.epochs[len(chain.epochs)-1]

	// A tip that is still waiting for its own boundary needs nothing but
	// patience; its activation instant is already public and signed.
	if now.Before(tip.ActivateAt) {
		return Plan{
			Action: ActionAwaitActivation, Epoch: tip.Epoch, Attempt: 1,
			DueAt:  tip.ActivateAt,
			Reason: "successor assembled and waiting for its public activation boundary",
		}, nil
	}

	// Past the tip's own retirement with no successor: the network is down
	// and the outgoing material must be erased regardless.
	if !now.Before(tip.RetireAt) {
		return Plan{
			Action: ActionRetire, Epoch: tip.Epoch, DueAt: tip.RetireAt,
			Reason: "active epoch reached its retirement boundary without a successor",
		}, nil
	}

	prepareAt := tip.RetireAt.Add(-policy.PrepareLead)
	if now.Before(prepareAt) {
		return Plan{
			Action: ActionIdle, Epoch: tip.Epoch, DueAt: prepareAt,
			Reason: "active epoch is serving; successor preparation is not yet due",
		}, nil
	}

	// Preparation is due. Which attempt depends only on how far past the
	// first preparation instant the public clock has moved.
	if !now.Before(prepareAt.Add(policy.EscalateAfter)) {
		return Plan{
			Action: ActionEscalate, Epoch: tip.Epoch + 1,
			Attempt: len(policy.RetryOffsets) + 1, DueAt: prepareAt.Add(policy.EscalateAfter),
			Reason: "public retry ladder exhausted; a membership transition is required",
		}, nil
	}
	attempt := 1
	for _, offset := range policy.RetryOffsets {
		if !now.Before(prepareAt.Add(offset)) {
			attempt++
		}
	}
	due := prepareAt
	if attempt > 1 {
		due = prepareAt.Add(policy.RetryOffsets[attempt-2])
	}
	return Plan{
		Action: ActionPrepareNext, Epoch: tip.Epoch + 1, Attempt: attempt, DueAt: due,
		Reason: fmt.Sprintf("successor ceremony attempt %d is due on the public schedule", attempt),
	}, nil
}

// NextDeadline reports the next instant at which the plan can change. An
// operator uses it to sleep rather than poll, and it too depends only on
// public state.
func (chain *Chain) NextDeadline(now time.Time, policy Policy) (time.Time, error) {
	if err := policy.validate(); err != nil {
		return time.Time{}, err
	}
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.halted || len(chain.epochs) == 0 {
		return time.Time{}, errors.New("no scheduled deadline")
	}
	tip := chain.epochs[len(chain.epochs)-1]
	prepareAt := tip.RetireAt.Add(-policy.PrepareLead)
	candidates := []time.Time{tip.ActivateAt, tip.RetireAt, prepareAt, prepareAt.Add(policy.EscalateAfter)}
	for _, offset := range policy.RetryOffsets {
		candidates = append(candidates, prepareAt.Add(offset))
	}
	best := time.Time{}
	for _, candidate := range candidates {
		if candidate.After(now) && (best.IsZero() || candidate.Before(best)) {
			best = candidate
		}
	}
	if best.IsZero() {
		return time.Time{}, errors.New("no scheduled deadline")
	}
	return best, nil
}
