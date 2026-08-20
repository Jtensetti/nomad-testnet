package airlock

import (
	"errors"
	"testing"
	"time"
)

func testSchedule() Schedule {
	return Schedule{
		Genesis:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Period:                10 * time.Minute,
		DepositCutoff:         2 * time.Minute,
		BatchSize:             8,
		MaxDepositsPerSession: 8,
	}
}

func TestScheduleRejectsPolicyThatCouldNotBePublic(t *testing.T) {
	base := testSchedule()
	cases := []struct {
		name     string
		mutate   func(*Schedule)
		contains string
	}{
		{"no genesis", func(s *Schedule) { s.Genesis = time.Time{} }, "genesis"},
		{"zero period", func(s *Schedule) { s.Period = 0 }, "period"},
		{"negative period", func(s *Schedule) { s.Period = -time.Minute }, "period"},
		{"zero cutoff", func(s *Schedule) { s.DepositCutoff = 0 }, "cutoff"},
		{"cutoff equals period", func(s *Schedule) { s.DepositCutoff = s.Period }, "cutoff"},
		{"cutoff exceeds period", func(s *Schedule) { s.DepositCutoff = s.Period + time.Second }, "cutoff"},
		{"batch of one", func(s *Schedule) { s.BatchSize = 1 }, "batch size"},
		{"batch of zero", func(s *Schedule) { s.BatchSize = 0 }, "batch size"},
		{"no per-session bound", func(s *Schedule) { s.MaxDepositsPerSession = 0 }, "per-session"},
		{"per-session bound above the batch", func(s *Schedule) { s.MaxDepositsPerSession = s.BatchSize + 1 }, "per-session"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			schedule := base
			testCase.mutate(&schedule)
			err := schedule.Validate()
			if err == nil {
				t.Fatalf("accepted %s", testCase.name)
			}
			if !errors.Is(err, ErrScheduleInvalid) {
				t.Errorf("error %v is not an ErrScheduleInvalid", err)
			}
		})
	}
}

// The release schedule is the visible shape of a publication epoch. If any of
// it could be derived from queue state, an observer reading boundaries off
// the wire would be reading publication volume.
func TestReleaseTimingIsAPureFunctionOfPublicParameters(t *testing.T) {
	schedule := testSchedule()
	for epoch := uint64(0); epoch < 5; epoch++ {
		opens, closes, err := schedule.DepositWindow(epoch)
		if err != nil {
			t.Fatal(err)
		}
		release, err := schedule.ReleaseAt(epoch)
		if err != nil {
			t.Fatal(err)
		}
		wantOpens := schedule.Genesis.Add(time.Duration(epoch) * schedule.Period)
		if !opens.Equal(wantOpens) {
			t.Errorf("epoch %d opens at %s, want %s", epoch, opens, wantOpens)
		}
		if !closes.Equal(wantOpens.Add(schedule.Period - schedule.DepositCutoff)) {
			t.Errorf("epoch %d closes at %s", epoch, closes)
		}
		if !release.Equal(wantOpens.Add(schedule.Period)) {
			t.Errorf("epoch %d releases at %s", epoch, release)
		}
		// Repeating the call must give the same answer: the schedule holds no
		// state that a deposit could have moved.
		again, _, _ := schedule.DepositWindow(epoch)
		if !again.Equal(opens) {
			t.Errorf("epoch %d deposit window is not deterministic", epoch)
		}
	}
}

func TestEpochAtCoversBoundariesAndRejectsPreGenesis(t *testing.T) {
	schedule := testSchedule()
	if _, err := schedule.EpochAt(schedule.Genesis.Add(-time.Nanosecond)); err == nil {
		t.Error("accepted an instant before genesis")
	}
	cases := []struct {
		offset time.Duration
		want   uint64
	}{
		{0, 0},
		{schedule.Period - time.Nanosecond, 0},
		{schedule.Period, 1},
		{3*schedule.Period + time.Second, 3},
	}
	for _, testCase := range cases {
		got, err := schedule.EpochAt(schedule.Genesis.Add(testCase.offset))
		if err != nil {
			t.Fatal(err)
		}
		if got != testCase.want {
			t.Errorf("offset %s is epoch %d, want %d", testCase.offset, got, testCase.want)
		}
	}
}
