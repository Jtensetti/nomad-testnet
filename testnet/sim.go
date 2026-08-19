package testnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-selection-firewall/firewall"
	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

type Result struct {
	ContentHash           [32]byte
	QueryBasin            uint64
	ObjectBasin           uint64
	HammingDistance       int
	SymbolsGenerated      int
	MixedBatch            int
	Reconstructed         bool
	ReaderTraceIdentical  bool
	ConstantBytesPerEpoch int
}

type rlncDecoder struct {
	symbols      []rlnc.Symbol
	k            int
	originalSize int
}

func (d *rlncDecoder) Add(fragment []byte) error {
	if len(fragment) < 4 {
		return errors.New("short symbol")
	}
	k := int(binary.BigEndian.Uint16(fragment[:2]))
	dataLen := int(binary.BigEndian.Uint16(fragment[2:4]))
	if k != d.k || len(fragment) != 4+k+dataLen {
		return errors.New("invalid symbol envelope")
	}
	d.symbols = append(d.symbols, rlnc.Symbol{Coeff: append([]byte(nil), fragment[4:4+k]...), Data: append([]byte(nil), fragment[4+k:]...)})
	return nil
}
func (d *rlncDecoder) Ready() bool {
	if len(d.symbols) < d.k {
		return false
	}
	_, err := rlnc.Decode(d.symbols, d.k, d.originalSize)
	return err == nil
}
func (d *rlncDecoder) Decode() ([]byte, error) { return rlnc.Decode(d.symbols, d.k, d.originalSize) }

func marshalSymbol(s rlnc.Symbol) ([]byte, error) {
	if len(s.Coeff) > 65535 || len(s.Data) > 65535 {
		return nil, errors.New("symbol too large")
	}
	out := make([]byte, 4+len(s.Coeff)+len(s.Data))
	binary.BigEndian.PutUint16(out[:2], uint16(len(s.Coeff)))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(s.Data)))
	copy(out[4:], s.Coeff)
	copy(out[4+len(s.Coeff):], s.Data)
	return out, nil
}

// Run exercises the current research stack end to end. The mix package models
// the unlinkability property; it is not deployable mixnet cryptography.
func Run(ctx context.Context, content []byte, semanticDescription, privateQuery string) (Result, error) {
	if len(content) == 0 {
		return Result{}, errors.New("empty content")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Result{}, err
	}
	root := sha256.Sum256(content)
	sig := ed25519.Sign(priv, root[:])

	emb := basin.HashEmbedder{Dims: 512}
	objVec, err := emb.Embed(ctx, semanticDescription)
	if err != nil {
		return Result{}, err
	}
	qVec, err := emb.Embed(ctx, privateQuery)
	if err != nil {
		return Result{}, err
	}
	quant := basin.Quantizer{}
	objBasin, err := quant.Basin(objVec)
	if err != nil {
		return Result{}, err
	}
	queryBasin, err := quant.Basin(qVec)
	if err != nil {
		return Result{}, err
	}

	enc, err := rlnc.NewEncoder(content, 128)
	if err != nil {
		return Result{}, err
	}
	batchSize := enc.K() * 4
	if batchSize < 64 {
		batchSize = 64
	}
	symbols := make(map[uint64]rlnc.Symbol, batchSize)
	tagged := make([]mix.TaggedCell, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		s, err := enc.Encode()
		if err != nil {
			return Result{}, err
		}
		tag := uint64(i + 1)
		symbols[tag] = s
		tc, err := mix.NewTagged(tag)
		if err != nil {
			return Result{}, err
		}
		tagged = append(tagged, tc)
	}
	mixed, err := mix.HonestMix(mix.Config{MinBatch: 64}, tagged)
	if err != nil {
		return Result{}, err
	}

	fragments := make([][]byte, 0, len(mixed))
	for _, tc := range mixed {
		raw, err := marshalSymbol(symbols[tc.Tag])
		if err != nil {
			return Result{}, err
		}
		fragments = append(fragments, raw)
	}
	dec := &rlncDecoder{k: enc.K(), originalSize: enc.OriginalSize()}
	got, err := reconstruct.Reconstruct(dec, fragments, reconstruct.Verifier{Root: root, PublicKey: pub, Signature: sig})
	if err != nil {
		return Result{}, fmt.Errorf("reconstruction: %w", err)
	}
	if string(got) != string(content) {
		return Result{}, errors.New("reconstructed content mismatch")
	}

	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return Result{}, err
	}
	netCfg := firewall.NetworkConfig{CellsPerEpoch: 16, CellSize: fabric.CellSize, PeerSlots: 8, PublicSeed: seed}
	idle := firewall.SelectionState{}
	active := firewall.SelectionState{PrivateQuery: privateQuery, SelectedBasins: []uint64{queryBasin}, ReconstructionIDs: [][32]byte{root}}
	same, err := firewall.SameObservableTrace(netCfg, 10000, idle, active)
	if err != nil {
		return Result{}, err
	}
	trace, err := fabric.Trace(fabric.Config{Tick: 1, CellsPerTick: int(netCfg.CellsPerEpoch)}, 1)
	if err != nil {
		return Result{}, err
	}

	return Result{ContentHash: root, QueryBasin: queryBasin, ObjectBasin: objBasin, HammingDistance: basin.HammingDistance(queryBasin, objBasin), SymbolsGenerated: batchSize, MixedBatch: len(mixed), Reconstructed: true, ReaderTraceIdentical: same, ConstantBytesPerEpoch: trace[0]}, nil
}
