package testnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-selection-firewall/firewall"
	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

const (
	testCellsPerEpoch = 16
	testCellInterval  = 20 * time.Millisecond
	testPeerSlots     = 4
	testMixMembers    = 2
)

type Result struct {
	ContentHash           [32]byte
	QueryBasin            uint64
	ObjectBasin           uint64
	HammingDistance       int
	SymbolsGenerated      int
	MixedBatch            int
	MixRounds             int
	ShuffleProofsVerified bool
	WireCellsObserved     int
	WireCellSize          int
	IdleCadenceValid      bool
	ActiveCadenceValid    bool
	IdleMinimumSpacing    time.Duration
	ActiveMinimumSpacing  time.Duration
	Reconstructed         bool
	ReaderTraceIdentical  bool
	ConstantBytesPerEpoch int
}

type packetDecoder struct {
	expectedGeneration rlnc.GenerationID
	k                  int
	symbolSize         int
	originalSize       int
	decoder            *rlnc.Decoder
}

func newPacketDecoder(generation rlnc.GenerationID, k, symbolSize, originalSize int) (*packetDecoder, error) {
	decoder, err := rlnc.NewDecoder(k, symbolSize, originalSize)
	if err != nil {
		return nil, err
	}
	return &packetDecoder{
		expectedGeneration: generation,
		k:                  k,
		symbolSize:         symbolSize,
		originalSize:       originalSize,
		decoder:            decoder,
	}, nil
}

func (d *packetDecoder) Add(fragment []byte) error {
	packet, err := rlnc.ParsePacket(fragment)
	if err != nil {
		return err
	}
	if packet.Generation != d.expectedGeneration {
		return errors.New("coded packet belongs to the wrong generation")
	}
	if packet.K != d.k || packet.SymbolSize != d.symbolSize || packet.OriginalSize != d.originalSize {
		return errors.New("coded packet dimensions changed within generation")
	}
	_, err = d.decoder.Add(packet.Symbol)
	return err
}

func (d *packetDecoder) Ready() bool { return d.decoder.Ready() }
func (d *packetDecoder) Decode() ([]byte, error) { return d.decoder.Decode() }

type privateActivity struct {
	queryBasin uint64
}

type wireShape struct {
	Index    int
	PeerSlot uint16
	Size     int
	Digest   [32]byte
}

type worldCapture struct {
	shapes         []wireShape
	cells          []mix.WireCell
	planDigest     [32]byte
	cadenceValid   bool
	minimumSpacing time.Duration
	activity       privateActivity
}

type captureResult struct {
	peerSlot uint16
	items    []fabric.Observation
	err      error
}

type taggedObservation struct {
	peerSlot uint16
	item     fabric.Observation
}

type activityFunc func(context.Context) (privateActivity, error)

// Run composes the v0.1 research stack. Publication is a local fixture: it is
// intentionally not claimed to be an anonymous publication airlock.
func Run(ctx context.Context, content []byte, semanticDescription, privateQuery string) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("context is required")
	}
	if len(content) == 0 {
		return Result{}, errors.New("content must not be empty")
	}
	if strings.TrimSpace(semanticDescription) == "" || strings.TrimSpace(privateQuery) == "" {
		return Result{}, errors.New("semantic description and private query are required")
	}

	embedder := basin.LexicalHashEmbedder{Dims: 512}
	quantizer := basin.Quantizer{Seed: sha256.Sum256([]byte("nomad-testnet-basin-profile-v1"))}
	objectVector, err := embedder.Embed(ctx, semanticDescription)
	if err != nil {
		return Result{}, err
	}
	objectBasin, err := quantizer.Basin(objectVector)
	if err != nil {
		return Result{}, err
	}

	_, publisherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Result{}, err
	}
	manifest, err := reconstruct.NewManifest(content, objectBasin, publisherKey)
	if err != nil {
		return Result{}, err
	}

	symbolSize, err := chooseSymbolSize(len(content))
	if err != nil {
		return Result{}, err
	}
	encoder, err := rlnc.NewEncoder(content, symbolSize)
	if err != nil {
		return Result{}, err
	}
	if encoder.K() > testCellsPerEpoch {
		return Result{}, errors.New("object exceeds the single-generation test profile")
	}

	var generation rlnc.GenerationID
	copy(generation[:], manifest.Generation[:])
	plainCells := make([]mix.PlainCell, testCellsPerEpoch)
	for i := range plainCells {
		var symbol rlnc.Symbol
		if i < encoder.K() {
			symbol, err = encoder.Systematic(i)
		} else {
			symbol, err = encoder.Encode()
		}
		if err != nil {
			return Result{}, err
		}
		packet, err := rlnc.NewPacket(generation, encoder.K(), encoder.SymbolSize(), encoder.OriginalSize(), symbol)
		if err != nil {
			return Result{}, err
		}
		encoded, err := packet.MarshalBinary()
		if err != nil {
			return Result{}, err
		}
		copy(plainCells[i][:], encoded)
	}

	mixPublicKey, mixPrivateKey, err := mix.GenerateKey()
	if err != nil {
		return Result{}, err
	}
	encrypted, err := mix.Encrypt(mixPublicKey, plainCells)
	if err != nil {
		return Result{}, err
	}
	mixed, rounds, err := mix.CommitteeMix(mixPublicKey, encrypted, testMixMembers)
	if err != nil {
		return Result{}, err
	}
	for i, round := range rounds {
		if err := mix.VerifyShuffle(mixPublicKey, round.Input, round.Output, round.Proof); err != nil {
			return Result{}, fmt.Errorf("verify mix round %d: %w", i, err)
		}
	}
	wireCells, err := mixed.MarshalWire()
	if err != nil {
		return Result{}, err
	}

	networkConfig := firewall.NetworkConfig{
		CellsPerEpoch: testCellsPerEpoch,
		CellSize:      fabric.CellSize,
		CellInterval:  testCellInterval,
		PeerSlots:     testPeerSlots,
		PublicSeed:    sha256.Sum256([]byte("nomad-testnet-public-network-v1")),
	}
	plan, err := firewall.Plan(networkConfig, 7)
	if err != nil {
		return Result{}, err
	}

	idle, err := captureWorld(ctx, wireCells, networkConfig, plan, nil)
	if err != nil {
		return Result{}, fmt.Errorf("idle world: %w", err)
	}
	activity := func(activityContext context.Context) (privateActivity, error) {
		queryVector, err := embedder.Embed(activityContext, privateQuery)
		if err != nil {
			return privateActivity{}, err
		}
		queryBasin, err := quantizer.Basin(queryVector)
		if err != nil {
			return privateActivity{}, err
		}
		ranked := reconstruct.Rank([]reconstruct.Candidate{{
			ID: manifest.Root, Basin: manifest.Basin, Score: 1,
		}}, queryBasin)
		if len(ranked) != 1 || ranked[0].ID != manifest.Root {
			return privateActivity{}, errors.New("local candidate selection failed")
		}
		return privateActivity{queryBasin: queryBasin}, nil
	}
	active, err := captureWorld(ctx, wireCells, networkConfig, plan, activity)
	if err != nil {
		return Result{}, fmt.Errorf("active world: %w", err)
	}

	receivedBatch, err := mix.ParseWire(active.cells)
	if err != nil {
		return Result{}, fmt.Errorf("parse captured mix cells: %w", err)
	}
	decrypted, err := mix.Decrypt(mixPrivateKey, receivedBatch)
	if err != nil {
		return Result{}, fmt.Errorf("decrypt captured mix cells: %w", err)
	}
	decoder, err := newPacketDecoder(generation, encoder.K(), encoder.SymbolSize(), encoder.OriginalSize())
	if err != nil {
		return Result{}, err
	}
	fragments := make([][]byte, len(decrypted))
	for i := range decrypted {
		fragments[i] = append([]byte(nil), decrypted[i][:]...)
	}
	recovered, err := reconstruct.Reconstruct(decoder, fragments, manifest.Verifier())
	if err != nil {
		return Result{}, fmt.Errorf("local reconstruction: %w", err)
	}
	if err := manifest.VerifyObject(recovered); err != nil {
		return Result{}, fmt.Errorf("manifest verification: %w", err)
	}
	if !reflect.DeepEqual(recovered, content) {
		return Result{}, errors.New("reconstructed content mismatch")
	}

	readerTraceIdentical := idle.planDigest == active.planDigest && reflect.DeepEqual(idle.shapes, active.shapes)
	return Result{
		ContentHash:           manifest.Root,
		QueryBasin:            active.activity.queryBasin,
		ObjectBasin:           objectBasin,
		HammingDistance:       basin.HammingDistance(active.activity.queryBasin, objectBasin),
		SymbolsGenerated:      len(plainCells),
		MixedBatch:            mixed.Len(),
		MixRounds:             len(rounds),
		ShuffleProofsVerified: true,
		WireCellsObserved:     len(active.cells),
		WireCellSize:          mix.WireCellSize,
		IdleCadenceValid:      idle.cadenceValid,
		ActiveCadenceValid:    active.cadenceValid,
		IdleMinimumSpacing:    idle.minimumSpacing,
		ActiveMinimumSpacing:  active.minimumSpacing,
		Reconstructed:         true,
		ReaderTraceIdentical:  readerTraceIdentical,
		ConstantBytesPerEpoch: len(plan) * fabric.CellSize,
	}, nil
}

func chooseSymbolSize(contentSize int) (int, error) {
	const packetPayloadCapacity = rlnc.PacketSize - rlnc.PacketHeaderSize
	for symbolSize := packetPayloadCapacity - 1; symbolSize > 0; symbolSize-- {
		k := (contentSize + symbolSize - 1) / symbolSize
		if k <= testCellsPerEpoch && k+symbolSize <= packetPayloadCapacity {
			return symbolSize, nil
		}
	}
	return 0, errors.New("object is too large for the single-generation test profile")
}

func captureWorld(
	ctx context.Context,
	cells []mix.WireCell,
	cfg firewall.NetworkConfig,
	plan []firewall.Emission,
	activity activityFunc,
) (worldCapture, error) {
	if len(cells) != len(plan) {
		return worldCapture{}, errors.New("wire cells and public plan differ in length")
	}
	epochDuration, err := cfg.EpochDuration()
	if err != nil {
		return worldCapture{}, err
	}
	worldContext, cancel := context.WithTimeout(ctx, 2*time.Second+5*epochDuration)
	defer cancel()

	observers := make([]*fabric.UDPObserver, cfg.PeerSlots)
	peers := make([]*net.UDPAddr, cfg.PeerSlots)
	for i := range observers {
		observer, err := fabric.ListenUDPObserver(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			for _, opened := range observers {
				if opened != nil {
					_ = opened.Close()
				}
			}
			return worldCapture{}, err
		}
		observers[i] = observer
		peers[i] = observer.LocalAddr()
	}
	defer func() {
		for _, observer := range observers {
			_ = observer.Close()
		}
	}()

	expectedByPeer := make([]int, cfg.PeerSlots)
	peerPlan := make([]uint16, len(plan))
	for i, emission := range plan {
		peerPlan[i] = emission.PeerSlot
		expectedByPeer[emission.PeerSlot]++
	}
	captureResults := make(chan captureResult, len(observers))
	startedCaptures := 0
	for i, expected := range expectedByPeer {
		if expected == 0 {
			continue
		}
		startedCaptures++
		go func(peerSlot uint16, count int) {
			items, err := observers[peerSlot].Capture(worldContext, count)
			captureResults <- captureResult{peerSlot: peerSlot, items: items, err: err}
		}(uint16(i), expected)
	}

	activityResults := make(chan struct {
		result privateActivity
		err    error
	}, 1)
	if activity == nil {
		activityResults <- struct {
			result privateActivity
			err    error
		}{}
	} else {
		go func() {
			result, err := activity(worldContext)
			activityResults <- struct {
				result privateActivity
				err    error
			}{result: result, err: err}
		}()
	}

	source, err := fabric.NewQueueSource(len(cells))
	if err != nil {
		return worldCapture{}, err
	}
	for _, wireCell := range cells {
		var cell fabric.Cell
		copy(cell[:], wireCell[:])
		if !source.Enqueue(cell) {
			return worldCapture{}, errors.New("network-domain queue rejected a planned cell")
		}
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return worldCapture{}, err
	}
	defer sender.Close()
	sink, err := fabric.NewUDPSink(sender, peers, peerPlan)
	if err != nil {
		return worldCapture{}, err
	}
	scheduler, err := fabric.NewScheduler(fabric.Config{
		Epoch:         epochDuration,
		CellsPerEpoch: len(cells),
		MaxLateness:   2 * cfg.CellInterval,
	}, source, sink)
	if err != nil {
		return worldCapture{}, err
	}
	if err := scheduler.RunCells(worldContext, len(cells)); err != nil {
		return worldCapture{}, err
	}

	tagged := make([]taggedObservation, 0, len(cells))
	for i := 0; i < startedCaptures; i++ {
		result := <-captureResults
		if result.err != nil {
			return worldCapture{}, result.err
		}
		for _, item := range result.items {
			tagged = append(tagged, taggedObservation{peerSlot: result.peerSlot, item: item})
		}
	}
	activityResult := <-activityResults
	if activityResult.err != nil {
		return worldCapture{}, activityResult.err
	}
	return normalizeCapture(cells, cfg, plan, tagged, activityResult.result)
}

func normalizeCapture(
	expected []mix.WireCell,
	cfg firewall.NetworkConfig,
	plan []firewall.Emission,
	observed []taggedObservation,
	activity privateActivity,
) (worldCapture, error) {
	if len(observed) != len(expected) {
		return worldCapture{}, fmt.Errorf("observed %d cells, want %d", len(observed), len(expected))
	}
	indexByDigest := make(map[[32]byte]int, len(expected))
	for i := range expected {
		digest := sha256.Sum256(expected[i][:])
		if _, exists := indexByDigest[digest]; exists {
			return worldCapture{}, errors.New("test fixture contains duplicate wire cells")
		}
		indexByDigest[digest] = i
	}

	shapes := make([]wireShape, len(expected))
	received := make([]mix.WireCell, len(expected))
	seen := make([]bool, len(expected))
	for _, tagged := range observed {
		index, ok := indexByDigest[tagged.item.Digest]
		if !ok || seen[index] {
			return worldCapture{}, errors.New("captured an unknown or duplicate wire cell")
		}
		if tagged.item.Size != int(plan[index].Size) || tagged.peerSlot != plan[index].PeerSlot {
			return worldCapture{}, errors.New("captured cell diverged from public size or peer plan")
		}
		seen[index] = true
		shapes[index] = wireShape{
			Index: index, PeerSlot: tagged.peerSlot, Size: tagged.item.Size, Digest: tagged.item.Digest,
		}
		copy(received[index][:], tagged.item.Cell[:])
	}

	sort.Slice(observed, func(i, j int) bool {
		return observed[i].item.ReceivedAt.Before(observed[j].item.ReceivedAt)
	})
	minimumSpacing := time.Duration(1<<63 - 1)
	for i := 1; i < len(observed); i++ {
		spacing := observed[i].item.ReceivedAt.Sub(observed[i-1].item.ReceivedAt)
		if spacing < minimumSpacing {
			minimumSpacing = spacing
		}
	}
	if len(observed) < 2 {
		minimumSpacing = 0
	}
	expectedSpan := time.Duration(len(observed)-1) * cfg.CellInterval
	actualSpan := observed[len(observed)-1].item.ReceivedAt.Sub(observed[0].item.ReceivedAt)
	cadenceValid := minimumSpacing >= cfg.CellInterval/10 &&
		actualSpan >= expectedSpan-2*cfg.CellInterval &&
		actualSpan <= expectedSpan+4*cfg.CellInterval

	return worldCapture{
		shapes:         shapes,
		cells:          received,
		planDigest:     firewall.ObservableDigest(plan),
		cadenceValid:   cadenceValid,
		minimumSpacing: minimumSpacing,
		activity:       activity,
	}, nil
}
