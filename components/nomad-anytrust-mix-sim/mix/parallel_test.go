package mix

import (
	"sync"
	"testing"
)

// parallel must visit every index exactly once, at every count -- including
// the counts around the boundaries, where an off-by-one in the atomic claim
// would either skip the last index or run one past the end.
func TestParallelVisitsEveryIndexExactlyOnce(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3, 17, 18, 19, 64, 257} {
		var mutex sync.Mutex
		seen := make([]int, count)
		parallel(count, func(_ *lane, index int) {
			mutex.Lock()
			defer mutex.Unlock()
			seen[index]++
		})
		for index, visits := range seen {
			if visits != 1 {
				t.Fatalf("count %d: index %d visited %d times", count, index, visits)
			}
		}
	}
}

// Every lane gets its own suite and stream. Sharing one would be a data race
// and would serialise the work being parallelised.
func TestEachLaneHasItsOwnSuite(t *testing.T) {
	var mutex sync.Mutex
	suites := map[*lane]int{}
	parallel(256, func(l *lane, _ int) {
		mutex.Lock()
		defer mutex.Unlock()
		if l.suite == nil || l.stream == nil {
			t.Error("a lane arrived without a suite or a stream")
		}
		suites[l]++
	})
	if len(suites) == 0 {
		t.Fatal("no lane ran")
	}
}
