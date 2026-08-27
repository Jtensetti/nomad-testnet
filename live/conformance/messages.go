package conformance

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	"github.com/Jtensetti/nomad-testnet/live/uplink"
)

// All returns every golden vector for the frozen wire protocol.
func All() ([]Vector, error) {
	var vectors []Vector
	for _, builder := range []func() ([]Vector, error){
		hopFrames,
		uplinkCells,
		objectManifests,
		signedTopologies,
	} {
		built, err := builder()
		if err != nil {
			return nil, err
		}
		vectors = append(vectors, built...)
	}
	return vectors, nil
}

// hopFrames covers the operator-to-operator cell: 1152 bytes of ciphertext,
// a 48-byte header and a 16-byte authentication tag inside it.
func hopFrames() ([]Vector, error) {
	var key [32]byte
	copy(key[:], DeterministicBytes("hop-pairwise-key", 32))
	context := hop.Context{
		NetworkID: "nomad-conformance",
		Epoch:     7,
		Receiver:  2,
	}
	copy(context.TopologyDigest[:], DeterministicBytes("topology-digest", 32))

	var stream hop.StreamID
	copy(stream[:], DeterministicBytes("stream-id", 16))

	build := func(name, description string, metadata hop.Metadata, sequence uint32) (Vector, error) {
		var cell fabric.Cell
		copy(cell[:hop.CiphertextSize], DeterministicBytes("hop-ciphertext-"+name, hop.CiphertextSize))
		if err := hop.Seal(&cell, metadata, 1, sequence, key, context); err != nil {
			return Vector{}, err
		}
		fields := map[string]string{
			"sender":     "1",
			"sequence":   strconv.FormatUint(uint64(sequence), 10),
			"flags":      strconv.FormatUint(uint64(metadata.Flags), 10),
			"ordinal":    strconv.FormatUint(uint64(metadata.Ordinal), 10),
			"batch_size": strconv.FormatUint(uint64(metadata.BatchSize), 10),
			"stream":     hex.EncodeToString(metadata.Stream[:]),
			"header_at":  strconv.Itoa(hop.CiphertextSize),
			"tag_at":     strconv.Itoa(hop.CiphertextSize + hop.HeaderSize - hop.TagSize),
		}
		return NewVector("hop-cell-v1", name, description, cell[:], fields), nil
	}

	work, err := hop.WorkMetadata(stream, 3, 8)
	if err != nil {
		return nil, err
	}
	workVector, err := build("work", "a relay cell carrying one batch fragment", work, 42)
	if err != nil {
		return nil, err
	}
	coverVector, err := build("cover",
		"a filler cell: identical size and cadence, zero stream and batch coordinates",
		hop.CoverMetadata(), 43)
	if err != nil {
		return nil, err
	}
	maximum, err := hop.WorkMetadata(stream, hop.MaximumBatch-1, hop.MaximumBatch)
	if err != nil {
		return nil, err
	}
	boundaryVector, err := build("work-batch-maximum",
		"the largest permitted batch coordinates, pinning the limit", maximum, ^uint32(0)-1)
	if err != nil {
		return nil, err
	}
	return []Vector{workVector, coverVector, boundaryVector}, nil
}

// uplinkCells cover the publisher-facing cell: an 8-byte cleartext sequence
// and one authenticated ciphertext over everything else, so that work and
// cover differ only inside it.
func uplinkCells() ([]Vector, error) {
	// The committee key is generated fresh and then discarded. It does not
	// reach the vector: the only bytes published here are the cleartext
	// sequence prefix, which is independent of every key. Using the
	// production seal path rather than hand-writing eight bytes is the point
	// -- the vector states what the encoder actually emits.
	committee, _, err := mix.GenerateKey()
	if err != nil {
		return nil, err
	}
	context := uplink.Context{
		NetworkID:     "nomad-conformance",
		Epoch:         7,
		EntryOperator: 1,
	}
	copy(context.TopologyDigest[:], DeterministicBytes("topology-digest", 32))
	session, err := uplink.NewSession(DeterministicBytes("uplink-shared-secret", 32), committee, context)
	if err != nil {
		return nil, err
	}

	// The inner committee layer is a real ElGamal encryption and therefore
	// randomised: two seals of the same fragment differ. A byte-exact vector
	// would not be reproducible, so what is pinned here is the *frame*: the
	// cleartext sequence prefix, the total length and the offsets a parser
	// must use. Indistinguishability of work and cover is asserted by tests
	// in live/uplink, not by a golden vector.
	var payload [uplink.PayloadSize]byte
	copy(payload[:], DeterministicBytes("uplink-fragment", uplink.PayloadSize))
	cell, err := session.SealWork(9, payload)
	if err != nil {
		return nil, err
	}
	prefix := append([]byte(nil), cell[:uplink.SequenceSize]...)
	fields := map[string]string{
		"sequence":            "9",
		"sequence_size":       strconv.Itoa(uplink.SequenceSize),
		"inner_size":          strconv.Itoa(uplink.InnerSize),
		"cell_size":           strconv.Itoa(fabric.CellSize),
		"ciphertext_is_fixed": "false",
		"note":                "the sealed body is randomised; only the frame is pinned",
	}
	return []Vector{
		NewVector("uplink-cell-frame-v1", "sequence-prefix",
			"the cleartext big-endian sequence counter that prefixes every uplink cell",
			prefix, fields),
	}, nil
}

// objectManifests cover the 228-byte signed manifest, which is the join
// between the network and local reconstruction.
func objectManifests() ([]Vector, error) {
	private := DeterministicKey("publisher")
	object := DeterministicBytes("object", 4096)
	manifest, err := reconstruct.NewManifest(object, 0xA5A5A5A5A5A5A5A5, private)
	if err != nil {
		return nil, err
	}
	encoded, err := manifest.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(encoded) != reconstruct.ManifestSize {
		return nil, fmt.Errorf("manifest is %d bytes, want %d", len(encoded), reconstruct.ManifestSize)
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("publisher key is not Ed25519")
	}
	fields := map[string]string{
		"manifest_size": strconv.Itoa(reconstruct.ManifestSize),
		"object_length": strconv.Itoa(len(object)),
		"basin":         "11936128518282651045",
		"publisher_key": base64.StdEncoding.EncodeToString(public),
	}
	return []Vector{
		NewVector("object-manifest-v1", "signed-4096-byte-object",
			"a manifest over a known object, pinning field order and the signed message",
			encoded, fields),
	}, nil
}

// signedTopologies cover the document a second implementation must parse
// before it can join anything: the peer set, the traffic class, the DKG
// profile, every operator's attestation and the authority signature.
//
// It is the admission format, so it is the one an interoperating
// implementation gets wrong first, and until now the corpus did not describe
// it at all. The validity window is fixed and deliberately wide; conformance
// checks parse, verify signatures and compare the canonical digest, which are
// clock-independent, and a consumer that also enforces the window should use
// the stated bounds rather than its own clock.
func signedTopologies() ([]Vector, error) {
	const (
		notBefore = "2020-01-01T00:00:00Z"
		notAfter  = "2100-01-01T00:00:00Z"
		startAt   = "2020-01-01T00:05:00Z"
	)
	build := func(operators int) (topology.Signed, error) {
		var session [32]byte
		copy(session[:], DeterministicBytes("topology-dkg-session", 32))
		document := topology.Document{
			Version: topology.Version, NetworkID: "nomad-conformance", Epoch: 7,
			NotBefore: notBefore, NotAfter: notAfter,
			Traffic: topology.TrafficClass{
				CellSize: topology.CellSize, CellIntervalMillis: 50,
				MaxLatenessMillis: 200, QueueCapacity: 256,
			},
			DKG: topology.DKGProfile{
				Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(session[:]),
				StartAt: startAt, PhaseDurationMillis: 30_000,
			},
			Operators: make([]topology.Operator, operators),
		}
		identities := make(map[string]ed25519.PrivateKey, operators)
		for index := range document.Operators {
			id := fmt.Sprintf("operator-%c", 'a'+index)
			identity := DeterministicKey("topology-identity-" + id)
			identities[id] = identity
			kexSeed := DeterministicBytes("topology-kex-"+id, 32)
			kex, err := ecdh.X25519().NewPrivateKey(kexSeed)
			if err != nil {
				return topology.Signed{}, err
			}
			// A DKG identity is an Edwards25519 point, so arbitrary bytes
			// will not decode. An Ed25519 public key is such a point in the
			// same encoding, and deriving it deterministically keeps the
			// vector reproducible. Nothing secret is published: only the
			// point appears in the document.
			dkgPublic := DeterministicKey("topology-dkg-" + id).Public().(ed25519.PublicKey)
			document.Operators[index] = topology.Operator{
				ID: id, Index: uint16(index),
				Endpoint:        fmt.Sprintf("198.51.100.%d:4200", index+1),
				PartialEndpoint: fmt.Sprintf("http://198.51.100.%d:4300", index+1),
				DKGEndpoint:     fmt.Sprintf("https://198.51.100.%d:4400", index+1),
				IdentityKey:     base64.StdEncoding.EncodeToString(identity.Public().(ed25519.PublicKey)),
				KEXKey:          base64.StdEncoding.EncodeToString(kex.PublicKey().Bytes()),
				DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic),
				PeerPlan:        []uint16{uint16((index + 1) % operators)},
			}
		}
		attested := document
		var err error
		for _, operator := range document.Operators {
			attested, err = topology.Attest(attested, operator.ID, identities[operator.ID])
			if err != nil {
				return topology.Signed{}, err
			}
		}
		return topology.Finalize(attested, DeterministicKey("topology-authority"))
	}

	var vectors []Vector
	for _, shape := range []struct {
		name        string
		description string
		operators   int
	}{
		{"topology-three-operators",
			"the minimum multi-operator ring: three operators, each attesting the whole document", 3},
		{"topology-eight-operators",
			"a wider ring, pinning per-operator ordering and peer-plan encoding at scale", 8},
	} {
		signed, err := build(shape.operators)
		if err != nil {
			return nil, err
		}
		encoded, err := topology.Encode(signed)
		if err != nil {
			return nil, err
		}
		verified, err := topology.Verify(encoded, DeterministicKey("topology-authority").
			Public().(ed25519.PublicKey), time.Time{})
		if err != nil {
			return nil, fmt.Errorf("%s does not verify: %w", shape.name, err)
		}
		vectors = append(vectors, NewVector("topology-document-v3", shape.name, shape.description,
			encoded, map[string]string{
				"network_id":       signed.Document.NetworkID,
				"epoch":            strconv.FormatUint(signed.Document.Epoch, 10),
				"operators":        strconv.Itoa(len(signed.Document.Operators)),
				"threshold":        strconv.FormatUint(uint64(signed.Document.DKG.Threshold), 10),
				"cell_size":        strconv.FormatUint(uint64(signed.Document.Traffic.CellSize), 10),
				"cell_interval_ms": strconv.FormatUint(uint64(signed.Document.Traffic.CellIntervalMillis), 10),
				"not_before":       notBefore,
				"not_after":        notAfter,
				"topology_digest":  hex.EncodeToString(verified.Digest[:]),
			}))
	}
	return vectors, nil
}
