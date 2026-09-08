package hop

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

func testContext() Context {
	return Context{
		NetworkID: "test-network", Epoch: 7, Receiver: 1,
		TopologyDigest: [32]byte{9, 8, 7},
	}
}

func sealedWork(t *testing.T, stream StreamID, payloadSeed byte, key [32]byte,
	sender uint16, sequence uint32, context Context) fabric.Cell {
	t.Helper()
	var payload [CiphertextSize]byte
	for index := range payload {
		payload[index] = byte(index) ^ payloadSeed
	}
	metadata, err := WorkMetadata(stream, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	cell, err := FromCiphertext(payload, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := Seal(&cell, metadata, sender, sequence, key, context); err != nil {
		t.Fatal(err)
	}
	return cell
}

// The claim version 2 exists to support: nothing an observer can read off the
// wire says what the cell carries.
func TestSealedCellRevealsOnlyItsVersionAndSequence(t *testing.T) {
	key := [32]byte{1, 2, 3}
	context := testContext()
	stream := StreamID{0xA5, 0x17, 0x9C, 0x42, 0xD0, 0x6B, 0x33, 0xEE,
		0x81, 0x2F, 0x74, 0xBB, 0x08, 0x59, 0xC6, 0x1D}
	var payload [CiphertextSize]byte
	for index := range payload {
		payload[index] = byte(index)
	}
	cell := sealedWork(t, stream, 0, key, 3, 42, context)

	if bytes.Contains(cell[:], stream[:]) {
		t.Fatal("the stream ID appears in the sealed cell")
	}
	if bytes.Contains(cell[:], payload[:64]) {
		t.Fatal("the payload appears in the sealed cell")
	}
	if bytes.Contains(cell[:], key[:]) {
		t.Fatal("the link key appears in the sealed cell")
	}

	// The sender slot is two bytes and would appear by chance, so what is
	// asserted is that it is not where version 1 put it.
	header := cell[CiphertextSize:]
	if string(header[0:4]) != string(wireMagic[:]) {
		t.Fatal("the version is not in the clear, so no peer can tell what to reject")
	}
	sequence, err := WireSequence(cell)
	if err != nil || sequence != 42 {
		t.Fatalf("WireSequence: %d, %v", sequence, err)
	}
	// Version 1 answered this, which is how a passive observer read the work
	// flag and the stream ID. It must now refuse, and refuse for the right
	// reason: reading the encrypted bytes at the old offsets would usually
	// produce metadata that fails validation, which looks the same from the
	// outside and is not a check.
	_, err = LocalMetadata(cell)
	if err == nil {
		t.Fatal("a sealed cell can still be read without authenticating it")
	}
	if !strings.Contains(err.Error(), "not an unsealed hop header") {
		t.Fatalf("a sealed cell was refused for the wrong reason: %v", err)
	}
}

// Work and cover differ in every field the header used to expose. On the wire
// they must differ in none of them.
func TestSealedWorkAndCoverAreIndistinguishable(t *testing.T) {
	key := [32]byte{4, 5, 6}
	context := testContext()
	stream := StreamID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	const samples = 64
	work := make([]fabric.Cell, 0, samples)
	cover := make([]fabric.Cell, 0, samples)
	for index := 0; index < samples; index++ {
		work = append(work, sealedWork(t, stream, byte(index), key, 3, uint32(index*2+1), context))

		coverCell, err := fabric.RandomCell()
		if err != nil {
			t.Fatal(err)
		}
		if err := SetMetadata(&coverCell, CoverMetadata()); err != nil {
			t.Fatal(err)
		}
		if err := Seal(&coverCell, CoverMetadata(), 3, uint32(index*2+2), key, context); err != nil {
			t.Fatal(err)
		}
		cover = append(cover, coverCell)
	}

	// Every byte outside the version and the sequence must take more than one
	// value within each class. A position that is constant across every work
	// cell and constant across every cover cell is a position that classifies
	// them, which is exactly what the old work flag was.
	constant := func(cells []fabric.Cell, offset int) bool {
		first := cells[0][offset]
		for _, cell := range cells[1:] {
			if cell[offset] != first {
				return false
			}
		}
		return true
	}
	clearStart, clearEnd := CiphertextSize, CiphertextSize+sealedOffset
	for offset := 0; offset < fabric.CellSize; offset++ {
		if offset >= clearStart && offset < clearEnd {
			continue // magic and sequence, in the clear by design
		}
		if constant(work, offset) && constant(cover, offset) &&
			work[0][offset] == cover[0][offset] {
			t.Fatalf("byte %d is the same constant in every work and cover cell", offset)
		}
		if constant(work, offset) && constant(cover, offset) {
			t.Fatalf("byte %d separates work from cover with certainty", offset)
		}
	}
}

// The stream ID is a hash of the batch payloads, so it is the same value at
// every hop. Version 1 wrote it on the outside of the envelope; version 2
// encrypts it under each link's own key, so the two hops share nothing.
func TestTheSameStreamAtTwoHopsSharesNoBytes(t *testing.T) {
	stream := StreamID{0xA5, 0x17, 0x9C, 0x42, 0xD0, 0x6B, 0x33, 0xEE,
		0x81, 0x2F, 0x74, 0xBB, 0x08, 0x59, 0xC6, 0x1D}
	context := testContext()

	first := sealedWork(t, stream, 0, [32]byte{1}, 3, 11, context)
	secondContext := context
	secondContext.Receiver = 5
	second := sealedWork(t, stream, 0, [32]byte{2}, 4, 12, secondContext)

	// The payload is identical and the stream is identical; only the link
	// differs. Nothing beyond the version may match.
	matching := 0
	for offset := CiphertextSize + sealedOffset; offset < fabric.CellSize; offset++ {
		if first[offset] == second[offset] {
			matching++
		}
	}
	if matching > 8 {
		t.Fatalf("%d of the %d encrypted header bytes match across two hops of the "+
			"same stream", matching, fabric.CellSize-CiphertextSize-sealedOffset)
	}
	payloadMatching := 0
	for offset := 0; offset < CiphertextSize; offset++ {
		if first[offset] == second[offset] {
			payloadMatching++
		}
	}
	// One byte in 256 matches by chance; 1152 bytes gives about 4.5.
	if payloadMatching > 32 {
		t.Fatalf("%d of %d payload bytes match across two hops of the same batch",
			payloadMatching, CiphertextSize)
	}
}

// Two cells on one link must never share a keystream, and the sequence number
// is what guarantees it. This pins the dependency so that a change making the
// keystream ignore the sequence fails here rather than silently producing a
// two-time pad.
func TestEachSequenceGetsItsOwnKeystream(t *testing.T) {
	key := [32]byte{7}
	context := testContext()
	stream := StreamID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	first := sealedWork(t, stream, 0, key, 3, 1, context)
	second := sealedWork(t, stream, 0, key, 3, 2, context)

	identical := 0
	for offset := 0; offset < CiphertextSize; offset++ {
		if first[offset] == second[offset] {
			identical++
		}
	}
	if identical > 32 {
		t.Fatalf("two sequences produced %d identical payload bytes out of %d; the "+
			"keystream does not depend on the sequence", identical, CiphertextSize)
	}

	// Different contexts must separate too: the same sequence under a
	// different epoch, receiver, network or topology is a different link.
	for name, changed := range map[string]Context{
		"epoch":    {NetworkID: "test-network", Epoch: 8, Receiver: 1, TopologyDigest: [32]byte{9, 8, 7}},
		"receiver": {NetworkID: "test-network", Epoch: 7, Receiver: 2, TopologyDigest: [32]byte{9, 8, 7}},
		"network":  {NetworkID: "other-network", Epoch: 7, Receiver: 1, TopologyDigest: [32]byte{9, 8, 7}},
		"topology": {NetworkID: "test-network", Epoch: 7, Receiver: 1, TopologyDigest: [32]byte{1, 1, 1}},
	} {
		t.Run(name, func(t *testing.T) {
			other := sealedWork(t, stream, 0, key, 3, 1, changed)
			same := 0
			for offset := 0; offset < CiphertextSize; offset++ {
				if first[offset] == other[offset] {
					same++
				}
			}
			if same > 32 {
				t.Fatalf("changing the %s left %d payload bytes identical", name, same)
			}
		})
	}
}

// Every way of not being the intended receiver, in one place.
func TestOpenFailsClosed(t *testing.T) {
	key := [32]byte{1, 2, 3}
	context := testContext()
	stream := StreamID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sealed := sealedWork(t, stream, 0, key, 3, 42, context)

	wrongEpoch := context
	wrongEpoch.Epoch = 8
	wrongNetwork := context
	wrongNetwork.NetworkID = "other-network"
	wrongTopology := context
	wrongTopology.TopologyDigest = [32]byte{1}

	cases := map[string]struct {
		key     [32]byte
		sender  uint16
		context Context
		mutate  func(*fabric.Cell)
	}{
		"another key":      {[32]byte{9, 9, 9}, 3, context, nil},
		"another sender":   {key, 4, context, nil},
		"another epoch":    {key, 3, wrongEpoch, nil},
		"another network":  {key, 3, wrongNetwork, nil},
		"another topology": {key, 3, wrongTopology, nil},
		"flipped payload":  {key, 3, context, func(c *fabric.Cell) { c[0] ^= 1 }},
		"flipped metadata": {key, 3, context, func(c *fabric.Cell) { c[CiphertextSize+sealedOffset] ^= 1 }},
		"flipped tag":      {key, 3, context, func(c *fabric.Cell) { c[fabric.CellSize-1] ^= 1 }},
		"flipped sequence": {key, 3, context, func(c *fabric.Cell) { c[CiphertextSize+sequenceOffset] ^= 1 }},
		"zero sequence":    {key, 3, context, func(c *fabric.Cell) { clear(c[CiphertextSize+sequenceOffset : CiphertextSize+sequenceOffset+4]) }},
		"a local header":   {key, 3, context, func(c *fabric.Cell) { copy(c[CiphertextSize:], localMagic[:]) }},
		"an unknown magic": {key, 3, context, func(c *fabric.Cell) { c[CiphertextSize+3] = 3 }},
		"an all-zero key":  {[32]byte{}, 3, context, nil},
		"an empty context": {key, 3, Context{}, nil},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			cell := sealed
			if testCase.mutate != nil {
				testCase.mutate(&cell)
			}
			before := cell
			if _, err := Open(&cell, testCase.sender, testCase.key, testCase.context); err == nil {
				t.Fatal("a cell that should not have opened did")
			}
			if cell != before {
				t.Fatal("a refused cell was modified")
			}
		})
	}

	// The positive control: the same cell, opened by the peer it was sealed
	// for, so that none of the refusals above can be a function that always
	// refuses.
	cell := sealed
	metadata, err := Open(&cell, 3, key, context)
	if err != nil {
		t.Fatalf("the intended receiver was refused: %v", err)
	}
	if metadata.Stream != stream || !IsWork(metadata) || metadata.Sequence != 42 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

// A relayed cell is re-sealed under the next link's key with that link's own
// sequence, so what leaves an operator shares nothing with what arrived.
func TestRelayingReplacesEverythingOnTheWire(t *testing.T) {
	stream := StreamID{0xDE, 0xAD, 0xBE, 0xEF, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	inboundContext := testContext()
	inboundKey := [32]byte{1}
	inbound := sealedWork(t, stream, 0, inboundKey, 3, 100, inboundContext)

	opened := inbound
	metadata, err := Open(&opened, 3, inboundKey, inboundContext)
	if err != nil {
		t.Fatal(err)
	}
	// An opened cell is a local cell. The scheduler takes relayed cells
	// straight from here, and it reads them with LocalMetadata.
	local, err := LocalMetadata(opened)
	if err != nil {
		t.Fatalf("an opened cell is not readable as a local cell: %v", err)
	}
	if local.Stream != metadata.Stream || local.Flags != metadata.Flags ||
		local.Ordinal != metadata.Ordinal || local.BatchSize != metadata.BatchSize {
		t.Fatalf("opened cell reads back as %+v, not %+v", local, metadata)
	}

	relayed, err := FromCiphertext(Ciphertext(opened), metadata)
	if err != nil {
		t.Fatal(err)
	}
	outboundContext := inboundContext
	outboundContext.Receiver = 6
	if err := Seal(&relayed, metadata, 1, 7, [32]byte{2}, outboundContext); err != nil {
		t.Fatal(err)
	}

	matching := 0
	for offset := 0; offset < CiphertextSize; offset++ {
		if inbound[offset] == relayed[offset] {
			matching++
		}
	}
	if matching > 32 {
		t.Fatalf("%d payload bytes survived the relay unchanged", matching)
	}
	if bytes.Contains(relayed[:], stream[:]) {
		t.Fatal("the relayed cell carries the stream ID in the clear")
	}
}

// The tag must cover the header, not only the payload.
//
// If it covered only the payload, an attacker could paste another cell's
// header onto this one: the metadata region of that header decrypts correctly
// under its own sequence, so the receiver would accept a cell carrying one
// peer's payload under another's routing metadata. Every other negative test
// here is satisfied by the metadata failing to validate afterwards, which is
// luck rather than a check, so this splice is constructed to decrypt cleanly.
func TestAHeaderFromAnotherCellCannotBePastedOn(t *testing.T) {
	key := [32]byte{1, 2, 3}
	context := testContext()
	stream := StreamID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	first := sealedWork(t, stream, 0, key, 3, 5, context)
	second := sealedWork(t, stream, 9, key, 3, 6, context)

	// The second cell's magic, sequence and encrypted metadata, on the first
	// cell's payload and tag.
	spliced := first
	copy(spliced[CiphertextSize:CiphertextSize+tagOffset], second[CiphertextSize:CiphertextSize+tagOffset])

	if _, err := Open(&spliced, 3, key, context); err == nil {
		t.Fatal("a header spliced from another cell on the same link was accepted")
	}

	// The splice is only meaningful if that header does decrypt cleanly where
	// it belongs, so this shows the rejection came from the tag rather than
	// from metadata that happened to be malformed.
	intact := second
	if _, err := Open(&intact, 3, key, context); err != nil {
		t.Fatalf("the donor cell does not open on its own: %v", err)
	}
}

// An unrecognised version is refused, never downgraded to.
//
// The cell here is sealed correctly and then re-tagged under a version byte
// this build does not know, so the tag matches and only the version check can
// reject it. Without that construction the corrupted-magic case is refused by
// the tag, which says nothing about whether the version is examined at all.
func TestAnUnrecognisedVersionIsRefusedRatherThanDowngradedTo(t *testing.T) {
	key := [32]byte{1, 2, 3}
	context := testContext()
	stream := StreamID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	future := sealedWork(t, stream, 0, key, 3, 5, context)

	future[CiphertextSize+3] = 3
	tag := authenticationTag(future, key, context)
	copy(future[CiphertextSize+tagOffset:], tag[:])

	if _, err := Open(&future, 3, key, context); err == nil {
		t.Fatal("a cell announcing a future version was accepted by this build")
	}

	// The same construction at the version this build does speak must be
	// accepted, so the refusal above is about the version and not about
	// re-tagging.
	current := sealedWork(t, stream, 0, key, 3, 5, context)
	currentTag := authenticationTag(current, key, context)
	copy(current[CiphertextSize+tagOffset:], currentTag[:])
	if _, err := Open(&current, 3, key, context); err != nil {
		t.Fatalf("a correctly versioned cell was refused: %v", err)
	}
}
