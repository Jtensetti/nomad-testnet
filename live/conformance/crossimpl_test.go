package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/conformance"
	"github.com/Jtensetti/nomad-testnet/live/hop"
)

// PROD-03 asks that two implementations interoperate for the public wire
// protocol "without sharing protocol code". conformance/reference/nomadwire.py
// is the second one: a different language, no shared build, no dependency
// beyond its standard library, written from docs/PROTOCOL.md rather than from
// this repository's Go.
//
// Writing it found two defects that the corpus alone had not.
//
// The specification described bytes 1152..1200 as "random representation
// padding, fresh filler, not application data". They are the hop header. An
// implementation built from that text could not interoperate at all -- it
// would put random bytes where the magic, sender slot, sequence and
// authentication tag belong.
//
// And the corpus published authenticated cells without the key or the context
// the tag is bound to, so no second implementation could check a single tag.
// A MAC vector without its key demonstrates that this encoder is
// self-consistent and nothing else.
//
// This test is the direction the Python script cannot run: cells the Python
// implementation produced, which this one has never seen, verified here.

type crossCell struct {
	Name      string `json:"name"`
	BytesHex  string `json:"bytes_hex"`
	Sender    uint16 `json:"sender"`
	Sequence  uint32 `json:"sequence"`
	Flags     uint16 `json:"flags"`
	Ordinal   uint16 `json:"ordinal"`
	BatchSize uint16 `json:"batch_size"`
	Stream    string `json:"stream"`
}

type crossOutput struct {
	ProducedBy     string      `json:"produced_by"`
	HopKey         string      `json:"conformance_hop_key"`
	TopologyDigest string      `json:"topology_digest"`
	NetworkID      string      `json:"network_id"`
	Epoch          uint64      `json:"epoch"`
	Receiver       uint16      `json:"receiver"`
	Cells          []crossCell `json:"cells"`
}

func TestCellsFromTheSecondImplementationVerifyHere(t *testing.T) {
	python := requireSecondImplementation(t)
	root := filepath.Join("..", "..")
	script := filepath.Join(root, "conformance", "reference", "crosscheck.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the second implementation is missing: %v", err)
	}
	emitted := filepath.Join(t.TempDir(), "python-cells.json")

	// Running it rather than reading a committed file: a fixture goes stale
	// silently, and a stale fixture is exactly the interoperability claim
	// this test exists to make impossible.
	// Cells sealed by this implementation right now, so an encoder that drifts
	// after the committed corpus was written is caught here rather than only
	// by the corpus check in CI. Mutating the header layout in encodeHeader
	// was, before this, invisible to every test in this package.
	fresh := filepath.Join(t.TempDir(), "go-cells.json")
	sealFreshCells(t, fresh)

	command := exec.Command(python, script,
		filepath.Join(root, "conformance", "wire-vectors.json"),
		"--emit", emitted, "--verify", fresh)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the second implementation failed against the published corpus:\n%s", output)
	}
	t.Logf("second implementation, against the corpus this one published:\n%s", output)

	// Every direction must actually have run. Without this the test passes
	// when a direction is silently skipped -- which is how a second
	// implementation stops covering a message type without anyone noticing.
	for _, direction := range []string{"A:", "C:", "E:", "F:", "G:"} {
		if !bytes.Contains(output, []byte(direction)) {
			t.Errorf("direction %s did not run:\n%s", direction, output)
		}
	}

	// A direction that ran is not a direction that checked anything. Each of
	// these reports how many documents it refused, and the floor is pinned
	// here so a list that shrinks on the other side fails on this one.
	//
	// The floors are minimums rather than equalities: the two implementations
	// enumerate their mutations differently -- the reference applies its
	// topology list to every topology vector, this one applies its list once
	// -- so requiring the numbers to match would be requiring them to be the
	// same program.
	for _, floor := range []struct {
		pattern string
		least   int
	}{
		{`C: refused (\d+) mutations`, 17},
		{`E: verified \d+ signed topologies and refused (\d+)`, 12},
		{`F: verified \d+ object manifest\(s\) and refused (\d+)`, 8},
		{`G: reproduced \d+ uplink frame derivation\(s\) and refused (\d+)`, 14},
	} {
		match := regexp.MustCompile(floor.pattern).FindSubmatch(output)
		if match == nil {
			t.Errorf("could not read a refusal count for %q from:\n%s", floor.pattern, output)
			continue
		}
		count, err := strconv.Atoi(string(match[1]))
		if err != nil {
			t.Fatal(err)
		}
		if count < floor.least {
			t.Errorf("the second implementation refused %d documents where it "+
				"refused %d before; a refusal list that shrinks is a check that "+
				"stopped checking", count, floor.least)
		}
	}

	encoded, err := os.ReadFile(emitted)
	if err != nil {
		t.Fatal(err)
	}
	var produced crossOutput
	if err := json.Unmarshal(encoded, &produced); err != nil {
		t.Fatal(err)
	}
	if len(produced.Cells) < 2 {
		t.Fatalf("the second implementation produced %d cells; nothing is being checked",
			len(produced.Cells))
	}

	var key [32]byte
	decodeInto(t, produced.HopKey, key[:])
	context := hop.Context{
		NetworkID: produced.NetworkID,
		Epoch:     produced.Epoch,
		Receiver:  produced.Receiver,
	}
	decodeInto(t, produced.TopologyDigest, context.TopologyDigest[:])

	work := map[string][][hop.CiphertextSize]byte{}
	for _, produced := range produced.Cells {
		cell := decodeCell(t, produced.Name, produced.BytesHex)
		metadata, err := hop.Open(&cell, produced.Sender, key, context)
		if err != nil {
			t.Errorf("%s, produced by the second implementation, was refused here: %v",
				produced.Name, err)
			continue
		}
		if metadata.Sequence != produced.Sequence || metadata.Flags != produced.Flags ||
			metadata.Ordinal != produced.Ordinal || metadata.BatchSize != produced.BatchSize {
			t.Errorf("%s: decoded %+v, the second implementation declared "+
				"sequence=%d flags=%d ordinal=%d batch=%d", produced.Name, metadata,
				produced.Sequence, produced.Flags, produced.Ordinal, produced.BatchSize)
		}
		if got := hex.EncodeToString(metadata.Stream[:]); got != produced.Stream {
			t.Errorf("%s: decoded stream %s, declared %s", produced.Name, got, produced.Stream)
		}
		if hop.IsWork(metadata) {
			work[produced.Stream] = append(work[produced.Stream], hop.Ciphertext(cell))
		}
	}

	// The stream ID is a hash the two implementations must agree on, and
	// agreement cannot be checked by verifying a tag: a wrong stream ID still
	// produces a valid tag over itself. Recompute it here from the payloads
	// the second implementation sent.
	if len(work) != 1 {
		t.Fatalf("expected one work stream from the second implementation, got %d", len(work))
	}
	for declared, payloads := range work {
		recomputed, err := hop.StreamFor(payloads)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(recomputed[:]); got != declared {
			t.Errorf("the two implementations disagree on the stream ID for the same "+
				"batch: this one computes %s, the second declared %s", got, declared)
		}
	}
}

// The other half of interoperating: a cell this implementation refuses must be
// refused by the second one too, and for the same reason. Two implementations
// that both accept everything also "interoperate".
func TestBothImplementationsRefuseTheSameCells(t *testing.T) {
	requireSecondImplementation(t)
	root := filepath.Join("..", "..")
	corpus := filepath.Join(root, "conformance", "wire-vectors.json")

	encoded, err := os.ReadFile(corpus)
	if err != nil {
		t.Fatal(err)
	}
	var published struct {
		Vectors []struct {
			Name     string            `json:"name"`
			Message  string            `json:"message"`
			BytesHex string            `json:"bytes_hex"`
			Fields   map[string]string `json:"fields"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(encoded, &published); err != nil {
		t.Fatal(err)
	}

	var subject struct {
		bytes  []byte
		fields map[string]string
	}
	for _, vector := range published.Vectors {
		if vector.Message == "hop-cell-v2" {
			subject.bytes = decodeHex(t, vector.BytesHex)
			subject.fields = vector.Fields
			break
		}
	}
	if subject.bytes == nil {
		t.Fatal("the corpus carries no hop-cell-v2 vector")
	}

	var key [32]byte
	decodeInto(t, subject.fields["conformance_hop_key"], key[:])
	context := hop.Context{
		NetworkID: subject.fields["network_id"],
		Epoch:     7,
		Receiver:  2,
	}
	decodeInto(t, subject.fields["topology_digest"], context.TopologyDigest[:])

	// The same mutations the second implementation refuses, refused here.
	// Their list lives in crosscheck.py and this is the mirror.
	//
	// The counts are not compared element for element -- the two sides
	// enumerate differently -- but neither list can quietly shrink: this one
	// fails if a case is removed, and the reference's reported counts are
	// floored in TestCellsFromTheSecondImplementationVerifyHere.
	mutations := []struct {
		name   string
		offset int
		value  []byte
	}{
		{"a flipped ciphertext byte", 0, []byte{subject.bytes[0] ^ 0x01}},
		{"a flipped tag byte", 1184, []byte{subject.bytes[1184] ^ 0x01}},
		{"a changed sequence", hop.CiphertextSize + 4, []byte{0, 0, 0, 99}},
		{"a zero sequence", hop.CiphertextSize + 4, []byte{0, 0, 0, 0}},
		{"a corrupted magic", hop.CiphertextSize, []byte("XXXX")},
		{"a downgraded version", hop.CiphertextSize + 3, []byte{1}},
		// Version 2 encrypts the routing metadata, so there is no sender
		// slot or flag field to change: what used to be those mutations is
		// now a flip somewhere in the sealed region, which the tag catches
		// before anything is decrypted.
		{"a flipped metadata byte", hop.CiphertextSize + 8,
			[]byte{subject.bytes[hop.CiphertextSize+8] ^ 0x01}},
		{"a flipped metadata byte at the end", hop.CiphertextSize + 31,
			[]byte{subject.bytes[hop.CiphertextSize+31] ^ 0x01}},
	}
	sender := uint16(1)
	for _, mutation := range mutations {
		mutated := append([]byte(nil), subject.bytes...)
		copy(mutated[mutation.offset:], mutation.value)
		var cell fabric.Cell
		copy(cell[:], mutated)
		if _, err := hop.Open(&cell, sender, key, context); err == nil {
			t.Errorf("this implementation accepted %s", mutation.name)
		}
	}

	// And the context bindings, each of which is a distinct cross-context
	// replay if it is not in the tag.
	var cell fabric.Cell
	copy(cell[:], subject.bytes)
	other := []struct {
		name    string
		key     [32]byte
		context hop.Context
	}{}
	wrongKey := key
	wrongKey[0] ^= 0x01
	other = append(other, struct {
		name    string
		key     [32]byte
		context hop.Context
	}{"a different pairwise key", wrongKey, context})
	for _, change := range []struct {
		name  string
		apply func(hop.Context) hop.Context
	}{
		{"a different epoch", func(c hop.Context) hop.Context { c.Epoch++; return c }},
		{"a different receiver", func(c hop.Context) hop.Context { c.Receiver++; return c }},
		{"a different network", func(c hop.Context) hop.Context {
			c.NetworkID += "-other"
			return c
		}},
		{"a different topology digest", func(c hop.Context) hop.Context {
			c.TopologyDigest[0] ^= 0x01
			return c
		}},
	} {
		other = append(other, struct {
			name    string
			key     [32]byte
			context hop.Context
		}{change.name, key, change.apply(context)})
	}
	for _, attempt := range other {
		candidate := cell
		if _, err := hop.Open(&candidate, sender, attempt.key, attempt.context); err == nil {
			t.Errorf("this implementation accepted the cell under %s", attempt.name)
		}
	}

	// The positive control: without it, an Open that refused everything
	// would pass every assertion above.
	candidate := cell
	if _, err := hop.Open(&candidate, sender, key, context); err != nil {
		t.Fatalf("the unmutated corpus cell was refused: %v", err)
	}
}

// sealFreshCells writes a batch this implementation seals at test time, in the
// shape the second implementation reads.
func sealFreshCells(t *testing.T, path string) {
	t.Helper()
	var key [32]byte
	copy(key[:], conformance.DeterministicBytes("hop-pairwise-key", 32))
	context := hop.Context{NetworkID: "nomad-conformance", Epoch: 7, Receiver: 2}
	copy(context.TopologyDigest[:], conformance.DeterministicBytes("topology-digest", 32))

	const batch = 3
	payloads := make([][hop.CiphertextSize]byte, batch)
	for index := range payloads {
		copy(payloads[index][:], conformance.DeterministicBytes(
			fmt.Sprintf("cross-fresh-%d", index), hop.CiphertextSize))
	}
	stream, err := hop.StreamFor(payloads)
	if err != nil {
		t.Fatal(err)
	}

	output := crossOutput{
		ProducedBy:     "live/conformance/crossimpl_test.go",
		HopKey:         hex.EncodeToString(key[:]),
		TopologyDigest: hex.EncodeToString(context.TopologyDigest[:]),
		NetworkID:      context.NetworkID,
		Epoch:          context.Epoch,
		Receiver:       context.Receiver,
	}
	const sender = uint16(1)
	for ordinal := range payloads {
		metadata, err := hop.WorkMetadata(stream, uint16(ordinal), batch)
		if err != nil {
			t.Fatal(err)
		}
		cell, err := hop.FromCiphertext(payloads[ordinal], metadata)
		if err != nil {
			t.Fatal(err)
		}
		sequence := uint32(500 + ordinal)
		if err := hop.Seal(&cell, metadata, sender, sequence, key, context); err != nil {
			t.Fatal(err)
		}
		output.Cells = append(output.Cells, crossCell{
			Name: fmt.Sprintf("go-work-%d", ordinal), BytesHex: hex.EncodeToString(cell[:]),
			Sender: sender, Sequence: sequence, Flags: metadata.Flags,
			Ordinal: metadata.Ordinal, BatchSize: metadata.BatchSize,
			Stream: hex.EncodeToString(stream[:]),
		})
	}

	var cover fabric.Cell
	copy(cover[:hop.CiphertextSize], conformance.DeterministicBytes("cross-fresh-cover", hop.CiphertextSize))
	if err := hop.SetMetadata(&cover, hop.CoverMetadata()); err != nil {
		t.Fatal(err)
	}
	if err := hop.Seal(&cover, hop.CoverMetadata(), sender, 600, key, context); err != nil {
		t.Fatal(err)
	}
	output.Cells = append(output.Cells, crossCell{
		Name: "go-cover", BytesHex: hex.EncodeToString(cover[:]), Sender: sender,
		Sequence: 600, Stream: hex.EncodeToString(make([]byte, 16)),
	})

	encoded, err := json.MarshalIndent(output, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func decodeHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func decodeInto(t *testing.T, encoded string, destination []byte) {
	t.Helper()
	decoded := decodeHex(t, encoded)
	if len(decoded) != len(destination) {
		t.Fatalf("expected %d bytes, got %d", len(destination), len(decoded))
	}
	copy(destination, decoded)
}

func decodeCell(t *testing.T, name, encoded string) fabric.Cell {
	t.Helper()
	decoded := decodeHex(t, encoded)
	if len(decoded) != fabric.CellSize {
		t.Fatalf("%s is %d bytes, not %d", name, len(decoded), fabric.CellSize)
	}
	var cell fabric.Cell
	copy(cell[:], decoded)
	return cell
}

// PROD-19 asks for interoperability evidence, and a corpus checked only by the
// encoder that produced it is not that. This is the structural half: every
// message type the corpus publishes must be named in the second
// implementation's driver, so adding a vector type without a consumer fails
// here rather than quietly widening the corpus without widening the evidence.
func TestEveryCorpusMessageHasASecondImplementation(t *testing.T) {
	root := filepath.Join("..", "..")
	corpus, err := os.ReadFile(filepath.Join(root, "conformance", "wire-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var published struct {
		Vectors []struct {
			Message string `json:"message"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(corpus, &published); err != nil {
		t.Fatal(err)
	}
	driver, err := os.ReadFile(filepath.Join(root, "conformance", "reference", "crosscheck.py"))
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]struct{}{}
	for _, vector := range published.Vectors {
		seen[vector.Message] = struct{}{}
	}
	if len(seen) < 4 {
		t.Fatalf("the corpus publishes only %d message types; the check is too weak to "+
			"mean anything", len(seen))
	}
	for message := range seen {
		if !bytes.Contains(driver, []byte(`"`+message+`"`)) {
			t.Errorf("the corpus publishes %s and the second implementation never names "+
				"it, so those vectors are checked only by the encoder that wrote them",
				message)
		}
	}
}
