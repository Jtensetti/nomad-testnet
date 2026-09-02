package mix

import (
	"runtime"
	"sync"
	"sync/atomic"

	"crypto/cipher"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
)

// lane is one goroutine's private cryptographic state.
//
// Kyber's suite carries a random stream that is not safe to share, and sharing
// one would serialise the work being parallelised. Every lane gets its own.
type lane struct {
	suite  *edwards25519.SuiteEd25519
	stream cipher.Stream
}

func (l *lane) point() kyber.Point   { return l.suite.Point() }
func (l *lane) scalar() kyber.Scalar { return l.suite.Scalar() }

// parallel runs work over [0, count) on up to GOMAXPROCS goroutines.
//
// Indices are claimed rather than partitioned, so an uneven cost per index
// does not leave one goroutine finishing long after the rest. work must write
// only to its own index; nothing here synchronises anything else.
func parallel(count int, work func(l *lane, index int)) {
	if count < 1 {
		return
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > count {
		workers = count
	}
	// Unreachable while GOMAXPROCS honours its contract of returning at least
	// one, and not covered by a test for that reason. It is here because this
	// function now guards five call sites: if the branch ever were reachable,
	// degrading to one worker is slow, where skipping the work would hand
	// Encrypt nil rows and recoverColumns all-zero cells, with no error.
	workers = max(workers, 1)
	var next atomic.Int64
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			local := &lane{suite: newSuite()}
			local.stream = local.suite.RandomStream()
			for {
				index := int(next.Add(1)) - 1
				if index >= count {
					return
				}
				work(local, index)
			}
		}()
	}
	group.Wait()
}
