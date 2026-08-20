package share

import (
	"fmt"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

// TopologyWindowGuard refuses threshold work outside the signed validity
// window of the topology that defines the epoch. It is the guard available
// wherever an epoch chain is not yet deployed, and it is strictly stronger
// than performing no retirement check at all: a share stops being usable at
// the boundary its own signed topology declares.
//
// It is weaker than an epoch chain, which additionally knows about
// emergency retirement by a successor. Deployments that carry a chain must
// use it instead.
type TopologyWindowGuard struct {
	Network topology.Verified
}

func (guard TopologyWindowGuard) ServesEpoch(epochNumber uint64, now time.Time) error {
	if guard.Network.Document.Epoch != epochNumber {
		return fmt.Errorf("epoch %d is not the epoch this operator serves", epochNumber)
	}
	notBefore, err := time.Parse(time.RFC3339, guard.Network.Document.NotBefore)
	if err != nil {
		return err
	}
	notAfter, err := time.Parse(time.RFC3339, guard.Network.Document.NotAfter)
	if err != nil {
		return err
	}
	if now.Before(notBefore) {
		return fmt.Errorf("epoch %d has not started", epochNumber)
	}
	if !now.Before(notAfter) {
		return fmt.Errorf("epoch %d is retired", epochNumber)
	}
	return nil
}
