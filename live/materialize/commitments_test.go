package materialize

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-testnet/live/batch"
)

// The descriptor's source commitments are what let the decoder refuse a
// polluted systematic symbol before it enters the basis. A descriptor that
// omits, truncates or malformes them must be rejected at verification, not
// tolerated with the check quietly off.
func TestDescriptorRequiresACommitmentPerSourceSymbol(t *testing.T) {
	fixture := buildDescriptorFixture(t)

	verify := func(descriptor batch.Descriptor) error {
		signed, err := batch.SignDescriptor(descriptor, fixture.authorityPrivate)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := batch.EncodeDescriptor(signed)
		if err != nil {
			t.Fatal(err)
		}
		_, err = batch.VerifyDescriptor(encoded, fixture.authorityPublic, fixture.network)
		return err
	}

	intact := fixture.generated.Descriptor
	if err := verify(intact); err != nil {
		t.Fatalf("intact descriptor rejected: %v", err)
	}
	if len(intact.SourceCommitments) != int(intact.K) {
		t.Fatalf("generator emitted %d commitments for k=%d",
			len(intact.SourceCommitments), intact.K)
	}

	missing := intact
	missing.SourceCommitments = nil
	if err := verify(missing); err == nil {
		t.Fatal("descriptor with no source commitments was accepted")
	}

	short := intact
	short.SourceCommitments = intact.SourceCommitments[:len(intact.SourceCommitments)-1]
	if err := verify(short); err == nil {
		t.Fatal("descriptor missing one source commitment was accepted")
	}

	malformed := intact
	malformed.SourceCommitments = append([]string(nil), intact.SourceCommitments...)
	malformed.SourceCommitments[0] = "zz" + malformed.SourceCommitments[0][2:]
	if err := verify(malformed); err == nil {
		t.Fatal("descriptor with a non-hex source commitment was accepted")
	}

	// The commitments sit under the authority signature: altering one
	// without re-signing must fail signature verification, so a relay
	// cannot re-point the pre-admission check at different data.
	tampered := intact
	tampered.SourceCommitments = append([]string(nil), intact.SourceCommitments...)
	first := []byte(tampered.SourceCommitments[0])
	if first[0] == '0' {
		first[0] = '1'
	} else {
		first[0] = '0'
	}
	tampered.SourceCommitments[0] = string(first)
	encoded, err := batch.EncodeDescriptor(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := batch.VerifyDescriptor(encoded, fixture.authorityPublic, fixture.network); err == nil ||
		!strings.Contains(err.Error(), "signature") {
		t.Fatalf("commitments swapped without re-signing: %v", err)
	}
}

// A polluted systematic symbol -- right coefficients, wrong data -- must be
// refused at admission by the materializer's decoder, against the signed
// commitments, rather than entering the basis and surfacing later as an
// envelope failure.
func TestMaterializerRefusesPollutedSystematicSymbolsPreAdmission(t *testing.T) {
	fixture := buildDescriptorFixture(t)
	encoded, err := batch.EncodeDescriptor(fixture.generated.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := batch.VerifyDescriptor(encoded, fixture.authorityPublic, fixture.network)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := newPacketDecoder(verified)
	if err != nil {
		t.Fatal(err)
	}

	encoder, err := rlnc.NewEncoder(fixture.payload, int(verified.Descriptor.SymbolSize))
	if err != nil {
		t.Fatal(err)
	}
	var generation rlnc.GenerationID
	generationBytes, err := hex.DecodeString(verified.Descriptor.Generation)
	if err != nil {
		t.Fatal(err)
	}
	copy(generation[:], generationBytes)

	wire := func(symbol rlnc.Symbol) []byte {
		packet, err := rlnc.NewPacket(generation, encoder.K(), encoder.SymbolSize(),
			encoder.OriginalSize(), symbol)
		if err != nil {
			t.Fatal(err)
		}
		encodedPacket, err := packet.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return encodedPacket
	}

	honest, err := encoder.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoder.Add(wire(honest)); err != nil {
		t.Fatalf("honest systematic symbol refused: %v", err)
	}

	// The fixture object fits one source symbol, so the polluted admission
	// is a second copy of symbol 0 with one bit of data flipped: same
	// systematic coefficients, a fresh fingerprint, wrong content.
	polluted, err := encoder.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	polluted.Data[7] ^= 0x01
	err = decoder.Add(wire(polluted))
	if !errors.Is(err, rlnc.ErrCommitmentMismatch) {
		t.Fatalf("polluted systematic symbol not refused pre-admission: %v", err)
	}
}
