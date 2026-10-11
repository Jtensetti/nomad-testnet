package firewall

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const MaxCellsPerEpoch = 1 << 20

// NetworkConfig contains every input that the emission planner is allowed to
// use. Private reader state intentionally has no representation in this package.
type NetworkConfig struct {
	CellsPerEpoch uint32
	CellSize      uint32
	CellInterval  time.Duration
	PeerSlots     uint16
	PublicSeed    [32]byte
}

func (c NetworkConfig) Validate() error {
	if c.CellsPerEpoch == 0 {
		return errors.New("cells per epoch must be positive")
	}
	if c.CellSize == 0 {
		return errors.New("cell size must be positive")
	}
	if c.CellsPerEpoch > MaxCellsPerEpoch {
		return errors.New("cells per epoch exceeds planner limit")
	}
	if c.CellInterval <= 0 {
		return errors.New("cell interval must be positive")
	}
	if c.PeerSlots == 0 {
		return errors.New("peer slots must be positive")
	}
	if uint64(c.CellInterval) > uint64(time.Duration(1<<63-1))/uint64(c.CellsPerEpoch) {
		return errors.New("epoch duration overflows time.Duration")
	}
	return nil
}

func (c NetworkConfig) EpochDuration() (time.Duration, error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}
	return time.Duration(c.CellsPerEpoch) * c.CellInterval, nil
}

type Emission struct {
	Epoch        uint64
	Slot         uint32
	CadenceIndex uint64
	Offset       time.Duration
	PeerSlot     uint16
	Size         uint32
}

// Plan is a pure function of public network configuration and epoch.
func Plan(cfg NetworkConfig, epoch uint64) ([]Emission, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if epoch > ^uint64(0)/uint64(cfg.CellsPerEpoch) {
		return nil, errors.New("cadence index overflows uint64")
	}
	base := epoch * uint64(cfg.CellsPerEpoch)
	out := make([]Emission, cfg.CellsPerEpoch)
	for i := uint32(0); i < cfg.CellsPerEpoch; i++ {
		h := sha256.New()
		_, _ = h.Write([]byte("nomad-selection-firewall-plan-v1"))
		_, _ = h.Write(cfg.PublicSeed[:])
		var b [12]byte
		binary.BigEndian.PutUint64(b[:8], epoch)
		binary.BigEndian.PutUint32(b[8:], i)
		_, _ = h.Write(b[:])
		sum := h.Sum(nil)
		peer := binary.BigEndian.Uint16(sum[:2]) % cfg.PeerSlots
		out[i] = Emission{
			Epoch:        epoch,
			Slot:         i,
			CadenceIndex: base + uint64(i),
			Offset:       time.Duration(i) * cfg.CellInterval,
			PeerSlot:     peer,
			Size:         cfg.CellSize,
		}
	}
	return out, nil
}

// ObservableDigest canonicalizes the fields a packet observer can attribute
// to the public plan. It is useful for two-world regression tests; matching
// digests are not a proof that an entire operating system is non-interfering.
func ObservableDigest(plan []Emission) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-observable-plan-v1"))
	var b [34]byte
	for _, emission := range plan {
		binary.BigEndian.PutUint64(b[0:8], emission.Epoch)
		binary.BigEndian.PutUint32(b[8:12], emission.Slot)
		binary.BigEndian.PutUint64(b[12:20], emission.CadenceIndex)
		binary.BigEndian.PutUint64(b[20:28], uint64(emission.Offset))
		binary.BigEndian.PutUint16(b[28:30], emission.PeerSlot)
		binary.BigEndian.PutUint32(b[30:34], emission.Size)
		_, _ = h.Write(b[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
