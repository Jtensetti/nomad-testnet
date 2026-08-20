package epoch

import (
	"crypto/sha256"
	"testing"
	"time"
)

func rotationChain(t *testing.T) (*fixture, *Chain, Verified) {
	t.Helper()
	f, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	return f, chain, genesis
}

func TestPlanFollowsThePublicSchedule(t *testing.T) {
	_, chain, genesis := rotationChain(t)
	// Genesis is active for two hours in the fixture, so a lead shorter than
	// that exercises every stage.
	policy := Policy{PrepareLead: 30 * time.Minute, RetryOffsets: []time.Duration{10 * time.Minute, 20 * time.Minute}, EscalateAfter: 25 * time.Minute}

	cases := []struct {
		name   string
		now    time.Time
		action Action
	}{
		{"before activation", genesis.ActivateAt.Add(-time.Minute), ActionAwaitActivation},
		{"serving", genesis.ActivateAt.Add(time.Minute), ActionIdle},
		{"preparation due", genesis.RetireAt.Add(-30 * time.Minute), ActionPrepareNext},
		{"first retry", genesis.RetireAt.Add(-20 * time.Minute), ActionPrepareNext},
		{"second retry", genesis.RetireAt.Add(-10 * time.Minute), ActionPrepareNext},
		{"ladder exhausted", genesis.RetireAt.Add(-time.Minute), ActionEscalate},
		{"retirement", genesis.RetireAt, ActionRetire},
		{"after retirement", genesis.RetireAt.Add(time.Hour), ActionRetire},
	}
	for _, testCase := range cases {
		plan, err := chain.PlanAt(testCase.now, policy)
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		if plan.Action != testCase.action {
			t.Fatalf("%s: expected %s, got %s (%s)", testCase.name, testCase.action, plan.Action, plan.Reason)
		}
	}
}

func TestPlanAttemptCountsFollowPublicOffsetsOnly(t *testing.T) {
	_, chain, genesis := rotationChain(t)
	policy := Policy{PrepareLead: 30 * time.Minute, RetryOffsets: []time.Duration{10 * time.Minute, 20 * time.Minute}, EscalateAfter: 25 * time.Minute}
	prepareAt := genesis.RetireAt.Add(-30 * time.Minute)
	for attempt, offset := range []time.Duration{0, 10 * time.Minute, 20 * time.Minute} {
		plan, err := chain.PlanAt(prepareAt.Add(offset), policy)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Attempt != attempt+1 {
			t.Fatalf("at offset %s expected attempt %d, got %d", offset, attempt+1, plan.Attempt)
		}
		if plan.Epoch != genesis.Epoch+1 {
			t.Fatalf("preparation must target the successor epoch, got %d", plan.Epoch)
		}
	}
}

// TestPlanIsDeterministicAndPublicOnly is the C-05 property applied to
// rotation: the same public state and clock always produce the same plan.
// PlanAt takes no parameter through which private state could enter, so a
// client that published, one that searched and one that sat idle are
// indistinguishable in what the lifecycle asks of them.
func TestPlanIsDeterministicAndPublicOnly(t *testing.T) {
	_, chain, genesis := rotationChain(t)
	policy := DefaultPolicy()
	policy.PrepareLead = 45 * time.Minute
	policy.RetryOffsets = []time.Duration{15 * time.Minute}
	policy.EscalateAfter = 30 * time.Minute
	probes := []time.Time{
		genesis.ActivateAt.Add(-time.Second),
		genesis.ActivateAt,
		genesis.RetireAt.Add(-46 * time.Minute),
		genesis.RetireAt.Add(-45 * time.Minute),
		genesis.RetireAt.Add(-30 * time.Minute),
		genesis.RetireAt,
	}
	for _, probe := range probes {
		first, err := chain.PlanAt(probe, policy)
		if err != nil {
			t.Fatal(err)
		}
		for repeat := 0; repeat < 5; repeat++ {
			again, err := chain.PlanAt(probe, policy)
			if err != nil {
				t.Fatal(err)
			}
			if again != first {
				t.Fatalf("plan at %s is not deterministic: %+v then %+v", probe, first, again)
			}
		}
	}
}

func TestHaltedChainPlansNothing(t *testing.T) {
	f := newFixture(t, 3)
	session := sha256.Sum256([]byte("rotation-halt"))
	topologyBytes, network := f.buildSignedTopology(t, 1, 2, genesisTimes(), session, 10)
	certificateBytes, _ := f.buildCertificate(t, network)
	firstEncoded, first := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network, topologyBytes, certificateBytes)
	other := genesisTimes()
	other.Retire = other.Retire.Add(time.Hour)
	secondEncoded, _ := f.buildDescriptor(t, nil, nil, TransitionGenesis, other, network, topologyBytes, certificateBytes)

	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(firstEncoded); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(secondEncoded); err == nil {
		t.Fatal("expected equivocation")
	}
	plan, err := chain.PlanAt(first.ActivateAt.Add(time.Minute), DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != ActionHalted {
		t.Fatalf("a halted chain must plan nothing, got %s", plan.Action)
	}
}

func TestPolicyValidationRejectsUnusableLadders(t *testing.T) {
	_, chain, genesis := rotationChain(t)
	bad := []Policy{
		{PrepareLead: 0},
		{PrepareLead: time.Hour, RetryOffsets: []time.Duration{0}, EscalateAfter: 30 * time.Minute},
		{PrepareLead: time.Hour, RetryOffsets: []time.Duration{2 * time.Hour}, EscalateAfter: 30 * time.Minute},
		{PrepareLead: time.Hour, RetryOffsets: []time.Duration{30 * time.Minute, 10 * time.Minute}, EscalateAfter: 45 * time.Minute},
		{PrepareLead: time.Hour, RetryOffsets: []time.Duration{30 * time.Minute}, EscalateAfter: 20 * time.Minute},
		{PrepareLead: time.Hour, RetryOffsets: []time.Duration{30 * time.Minute}},
	}
	for index, policy := range bad {
		if _, err := chain.PlanAt(genesis.ActivateAt, policy); err == nil {
			t.Fatalf("policy %d must be rejected", index)
		}
	}
}

func TestNextDeadlineAdvancesMonotonically(t *testing.T) {
	_, chain, genesis := rotationChain(t)
	policy := Policy{PrepareLead: 30 * time.Minute, RetryOffsets: []time.Duration{10 * time.Minute}, EscalateAfter: 20 * time.Minute}
	previous := genesis.ActivateAt.Add(-time.Hour)
	for step := 0; step < 5; step++ {
		next, err := chain.NextDeadline(previous, policy)
		if err != nil {
			break
		}
		if !next.After(previous) {
			t.Fatalf("deadline did not advance: %s then %s", previous, next)
		}
		previous = next
	}
}
