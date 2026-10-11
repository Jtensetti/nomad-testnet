package materialize

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-testnet/live/batch"
)

// A Byzantine campaign at the boundary the criterion names: the materializer's
// own decoder and verifier, fed fragments a hostile relay could produce.
//
// The claim under test is not that reconstruction succeeds. A dense coded
// symbol with wrong data cannot be checked before admission over GF(2^8), so a
// hostile relay can always deny a generation, and the campaign confirms it
// does. The claim is that corruption is never *accepted*: whatever the
// pollution rate, the materializer either reproduces the published object
// exactly or reports an error. It must never hand a caller bytes that differ
// from the signed content hash.
func TestByzantinePollutionNeverYieldsAcceptedCorruption(t *testing.T) {
	fixture := buildDescriptorFixture(t)
	encoded, err := batch.EncodeDescriptor(fixture.generated.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := batch.VerifyDescriptor(encoded, fixture.authorityPublic, fixture.network)
	if err != nil {
		t.Fatal(err)
	}
	verifier := reconstruct.Verifier{
		Root: verified.Root, PublicKey: verified.Publisher, Signature: verified.Signature,
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

	marshal := func(symbol rlnc.Symbol) []byte {
		packet, err := rlnc.NewPacket(generation, encoder.K(), encoder.SymbolSize(),
			encoder.OriginalSize(), symbol)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := packet.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}

	exact, denied, corrupted := 0, 0, 0
	for _, pollution := range []int{0, 10, 25, 50, 75, 100} {
		for trial := 0; trial < 12; trial++ {
			source := rand.New(rand.NewSource(int64(pollution)*1000 + int64(trial)))
			fragments := make([][]byte, 0, encoder.K()*4)
			for index := 0; index < encoder.K()*4; index++ {
				if source.Intn(100) < pollution {
					// Dense hostile symbol: well-formed coefficients that
					// raise the rank, data that is not the code word.
					coeff := make([]byte, encoder.K())
					data := make([]byte, encoder.SymbolSize())
					source.Read(coeff)
					source.Read(data)
					coeff[source.Intn(encoder.K())] |= 1
					fragments = append(fragments, marshal(rlnc.Symbol{Coeff: coeff, Data: data}))
					continue
				}
				honest, err := encoder.Systematic(index % encoder.K())
				if err != nil {
					t.Fatal(err)
				}
				fragments = append(fragments, marshal(honest))
			}

			decoder, err := newPacketDecoder(verified)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := reconstruct.Reconstruct(decoder, fragments, verifier)
			switch {
			case err != nil:
				denied++
			case bytes.Equal(recovered, fixture.payload):
				exact++
			default:
				corrupted++
				t.Errorf("pollution %d%% trial %d: reconstruction returned %d bytes that "+
					"are not the published object, and reported success",
					pollution, trial, len(recovered))
			}
		}
	}
	if corrupted != 0 {
		t.Fatalf("%d accepted corruptions", corrupted)
	}
	if exact == 0 {
		t.Fatal("no trial reconstructed the object; the campaign proved nothing about success")
	}
	if denied == 0 {
		t.Fatal("no trial was denied; the pollution never reached the decoder")
	}
	t.Logf("exact=%d denied=%d accepted-corruptions=%d", exact, denied, corrupted)
}

// Generation binding: a symbol carrying a different generation must be refused
// by the materializer's decoder even when its dimensions are right, so cells
// from another object cannot be spliced into this reconstruction.
func TestDecoderRefusesForeignGenerationSymbols(t *testing.T) {
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
	symbol, err := encoder.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	var foreign rlnc.GenerationID
	foreign[0] = 0xFF
	packet, err := rlnc.NewPacket(foreign, encoder.K(), encoder.SymbolSize(),
		encoder.OriginalSize(), symbol)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := decoder.Add(wire); err == nil {
		t.Fatal("a symbol from a different generation was admitted")
	}
	if decoder.Ready() {
		t.Fatal("a foreign-generation symbol advanced the decoder")
	}
}
