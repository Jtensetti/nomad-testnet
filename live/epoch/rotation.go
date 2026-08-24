package epoch

import (
	"errors"
	"fmt"
	"time"
)

// Action is what the lifecycle requires of an operator at a given instant.
type Action int

const (
	ActionIdle Action = iota
	ActionPrepareNext
	ActionAwaitActivation
	ActionRetire
	ActionEscalate
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

// Policy is public rotation configuration; none of it is derived from private
// user state, queue depth, publication state or reader activity.
type Policy struct {
	PrepareLead   time.Duration
	RetryOffsets  []time.Duration
	EscalateAfter time.Duration
}

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
	Action  Action
	Epoch   uint64
	Attempt int
	DueAt   time.Time
	Reason  string
}

// PlanAt is the schedule-only planner retained for tests and callers that do
// not own private epoch material. Operators that hold threshold shares MUST
// use PlanAtForOperator, which additionally blocks progression until retired
// private material has a durable signed erasure acknowledgement.
func (chain *Chain) PlanAt(now time.Time, policy Policy) (Plan, error) {
	if err := policy.validate(); err != nil {
		return Plan{}, err
	}
	chain.mu.Lock()
	defer chain.mu.Unlock()
	return chain.planAtLocked(now, policy), nil
}

func (chain *Chain) planAtLocked(now time.Time, policy Policy) Plan {
	if chain.halted {
		return Plan{Action: ActionHalted, Reason: "chain halted on recorded equivocation"}
	}
	if len(chain.epochs) == 0 {
		return Plan{Action: ActionIdle, Reason: "no genesis epoch yet"}
	}
	tip := chain.epochs[len(chain.epochs)-1]
	if now.Before(tip.ActivateAt) {
		return Plan{
			Action: ActionAwaitActivation, Epoch: tip.Epoch, Attempt: 1,
			DueAt: tip.ActivateAt,
			Reason: "successor assembled and waiting for its public activation boundary",
		}
	}
	if !now.Before(tip.RetireAt) {
		return Plan{
			Action: ActionRetire, Epoch: tip.Epoch, DueAt: tip.RetireAt,
			Reason: "active epoch reached its retirement boundary without a successor",
		}
	}

	prepareAt := tip.RetireAt.Add(-policy.PrepareLead)
	if now.Before(prepareAt) {
		return Plan{
			Action: ActionIdle, Epoch: tip.Epoch, DueAt: prepareAt,
			Reason: "active epoch is serving; successor preparation is not yet due",
		}
	}
	if !now.Before(prepareAt.Add(policy.EscalateAfter)) {
		return Plan{
			Action: ActionEscalate, Epoch: tip.Epoch + 1,
			Attempt: len(policy.RetryOffsets) + 1, DueAt: prepareAt.Add(policy.EscalateAfter),
			Reason: "public retry ladder exhausted; a membership transition is required",
		}
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
	}
}

// NextDeadline reports the next public instant at which the schedule can
// change. Operator loops call PlanAtForOperator before sleeping so overdue
// unacknowledged retirement is handled immediately rather than hidden by a
// future deadline.
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
