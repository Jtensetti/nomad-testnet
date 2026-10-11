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

// Sharing an operand across lanes is safe only while kyber treats scalars and
// points as read-only arguments. Encrypt, EncryptCell and
// CreatePartialDecryption all rest on that rather than cloning per index, so
// it is held here: the same scalar and point used concurrently from many
// goroutines must give the answer a sequential run gives, and must come back
// unchanged.
func TestSharedOperandsSurviveConcurrentUse(t *testing.T) {
	s := newSuite()
	secret := s.Scalar().Pick(s.RandomStream())
	base := s.Point().Mul(s.Scalar().Pick(s.RandomStream()), nil)

	before, err := secret.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	basePoint, err := base.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want, err := s.Point().Mul(secret, base).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	const count = 512
	got := make([][]byte, count)
	parallel(count, func(l *lane, index int) {
		encoded, err := l.point().Mul(secret, base).MarshalBinary()
		if err != nil {
			t.Error(err)
			return
		}
		got[index] = encoded
	})
	for index, encoded := range got {
		if string(encoded) != string(want) {
			t.Fatalf("concurrent use %d produced a different product than a "+
				"sequential one; a shared operand is being mutated", index)
		}
	}

	after, _ := secret.MarshalBinary()
	if string(after) != string(before) {
		t.Fatal("the shared scalar changed during concurrent use")
	}
	afterPoint, _ := base.MarshalBinary()
	if string(afterPoint) != string(basePoint) {
		t.Fatal("the shared point changed during concurrent use")
	}
}
