package epoch

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorInputs are fixed, human-auditable descriptor field values. The
// embedded topology and certificate are opaque length-prefixed blobs at the
// encoding layer, so fixed test byte strings pin the encoding exactly and
// keep the published vectors reproducible without a randomized DKG.
func vectorInputs() []struct {
	Name       string
	Descriptor Descriptor
} {
	zero := hex.EncodeToString(make([]byte, 32))
	previous := make([]byte, 32)
	for index := range previous {
		previous[index] = byte(index)
	}
	return []struct {
		Name       string
		Descriptor Descriptor
	}{
		{
			Name: "genesis-empty-embedded",
			Descriptor: Descriptor{
				Version: Version, PreviousEpochDigest: zero, Transition: TransitionGenesis,
				ActivateAt: "2026-01-01T00:00:00Z", RetireAt: "2026-01-08T00:00:00Z",
				Topology: "", DKGCertificate: "", UplinkProfile: "",
			},
		},
		{
			Name: "genesis-with-embedded-bytes",
			Descriptor: Descriptor{
				Version: Version, PreviousEpochDigest: zero, Transition: TransitionGenesis,
				ActivateAt: "2026-01-01T00:00:00Z", RetireAt: "2026-01-08T00:00:00Z",
				Topology:       base64.StdEncoding.EncodeToString([]byte("topology-bytes")),
				DKGCertificate: base64.StdEncoding.EncodeToString([]byte("certificate-bytes")),
				UplinkProfile:  "",
			},
		},
		{
			Name: "scheduled-transition",
			Descriptor: Descriptor{
				Version: Version, PreviousEpochDigest: hex.EncodeToString(previous), Transition: TransitionScheduled,
				ActivateAt: "2026-01-08T00:00:00Z", RetireAt: "2026-01-15T00:00:00Z",
				Topology:       base64.StdEncoding.EncodeToString([]byte("topology-bytes")),
				DKGCertificate: base64.StdEncoding.EncodeToString([]byte("certificate-bytes")),
				UplinkProfile:  "",
			},
		},
		{
			Name: "emergency-transition",
			Descriptor: Descriptor{
				Version: Version, PreviousEpochDigest: hex.EncodeToString(previous), Transition: TransitionEmergency,
				ActivateAt: "2026-01-09T12:30:45Z", RetireAt: "2026-01-16T00:00:00Z",
				Topology:       base64.StdEncoding.EncodeToString([]byte("topology-bytes")),
				DKGCertificate: base64.StdEncoding.EncodeToString([]byte("certificate-bytes")),
				UplinkProfile:  "",
			},
		},
	}
}

const vectorPath = "testdata/epoch-descriptor-vectors.json"

// TestPublishedVectorsMatch regenerates every vector and compares it to the
// committed file. Run with NOMAD_WRITE_VECTORS=1 to refresh the file after an
// intentional, reviewed encoding change.
func TestPublishedVectorsMatch(t *testing.T) {
	generated := make([]Vector, 0, len(vectorInputs()))
	for _, input := range vectorInputs() {
		vector, err := BuildVector(input.Name, input.Descriptor)
		if err != nil {
			t.Fatalf("%s: %v", input.Name, err)
		}
		generated = append(generated, vector)
	}
	encoded, err := json.MarshalIndent(generated, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	if os.Getenv("NOMAD_WRITE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("regenerated published vectors")
		return
	}

	committed, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("published vectors are missing; regenerate with NOMAD_WRITE_VECTORS=1: %v", err)
	}
	if string(committed) != string(encoded) {
		t.Fatal("published epoch descriptor vectors do not match the current encoder")
	}

	var parsed []Vector
	if err := json.Unmarshal(committed, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, vector := range parsed {
		if err := CheckVector(vector); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVectorEncodingIsUnambiguous(t *testing.T) {
	// Length prefixes must prevent field-boundary confusion: moving a byte
	// from one field to the next must change the canonical preimage.
	left := Descriptor{
		Version: Version, PreviousEpochDigest: hex.EncodeToString(make([]byte, 32)), Transition: TransitionGenesis,
		ActivateAt: "2026-01-01T00:00:00Z", RetireAt: "2026-01-08T00:00:00Z",
		Topology:       base64.StdEncoding.EncodeToString([]byte("ab")),
		DKGCertificate: base64.StdEncoding.EncodeToString([]byte("c")),
	}
	right := left
	right.Topology = base64.StdEncoding.EncodeToString([]byte("a"))
	right.DKGCertificate = base64.StdEncoding.EncodeToString([]byte("bc"))

	leftBytes, err := CanonicalBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	rightBytes, err := CanonicalBytes(right)
	if err != nil {
		t.Fatal(err)
	}
	if string(leftBytes) == string(rightBytes) {
		t.Fatal("canonical encoding must not be ambiguous across field boundaries")
	}
}

func TestCheckVectorDetectsTampering(t *testing.T) {
	vector, err := BuildVector("tamper", vectorInputs()[2].Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	tampered := vector
	tampered.DigestHex = hex.EncodeToString(make([]byte, 32))
	if err := CheckVector(tampered); err == nil {
		t.Fatal("a tampered digest must be detected")
	}
	tampered = vector
	tampered.ActivateAt = "2026-01-08T00:00:01Z"
	if err := CheckVector(tampered); err == nil {
		t.Fatal("a tampered input must change the recomputed digest")
	}
}
