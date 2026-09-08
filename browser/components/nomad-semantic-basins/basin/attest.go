package basin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// A basin ID decides which objects a reader ends up fetching. It is a function
// of the embedding, and the embedding is a function of whatever model the local
// service happens to be running. So a model that changes underneath a reader
// silently moves every one of their basins, and nothing in the system notices:
// the embeddings still look like embeddings, the quantizer still quantizes, and
// the reader simply starts pulling a different part of the catalogue than
// everyone still on the old model.
//
// What is needed is "reproducible model identity". This file supplies the
// reproducible half and is careful about the rest.
//
// It cannot establish *authenticity*. The embedding service is a separate
// process on loopback; nothing it says about which model it loaded can be
// checked, and a service willing to lie about its model is willing to lie about
// a hash of it. What can be established is that the service behaves now as it
// behaved when the attestation was recorded, and that is the property the
// system actually depends on.
//
// The fingerprint is taken over quantized basins rather than raw vectors. That
// is deliberate on both sides: floating-point embedding output can differ in
// the last bits between runs, kernels and hardware without meaning anything,
// while a change large enough to move a basin is by definition a change that
// moves what a reader fetches. Digesting the floats would produce an
// attestation that fails constantly for no reason, and one that fails
// constantly gets disabled.

// AttestationVersion is the frozen label for a model fingerprint.
const AttestationVersion = "nomad-basin-model-attestation-v1"

var (
	// ErrModelChanged reports that the service no longer behaves as it did
	// when the attestation was recorded.
	ErrModelChanged = errors.New("embedding model behaviour has changed since attestation")
	// ErrProbeUnusable reports that the probe set cannot fingerprint anything.
	ErrProbeUnusable = errors.New("probe set cannot distinguish a model")
)

// Attestation is a behavioural fingerprint of one embedding service.
//
// Every field is public: the probes are fixed strings chosen when the
// deployment is configured, never a reader's query, and the digest is over
// their basins. Nothing here can carry private activity, which is what allows
// an attestation to be published, compared between operators, and re-checked on
// a fixed schedule.
type Attestation struct {
	Version string `json:"version"`
	// Model is what the service was asked for. It is recorded because it is
	// useful to a human reading a mismatch report, and it is deliberately not
	// what the digest trusts.
	Model string `json:"model"`
	// Probes are the fixed public inputs, in the order they were measured.
	Probes []string `json:"probes"`
	// QuantizerSeed ties the fingerprint to the quantizer that produced it.
	// The same model under a different seed yields different basins, so an
	// attestation is meaningless without it.
	QuantizerSeed string `json:"quantizer_seed"`
	// Digest is over the version, model, seed, probes and their basins.
	Digest string `json:"digest"`
}

// MinimumProbes is the smallest probe set that fingerprints anything useful.
//
// One probe gives 64 bits that a service could match by returning a constant;
// several probes with distinct basins establish that the service is
// discriminating between inputs at all.
const MinimumProbes = 4

// Attest records how a service behaves on a fixed probe set.
//
// The probes must be fixed public strings decided by deployment policy. Passing
// anything derived from a reader's activity would turn a published artefact
// into a channel, which is why this takes them as an explicit argument rather
// than sampling anything.
func Attest(ctx context.Context, embedder Embedder, quantizer Quantizer,
	model string, probes []string) (Attestation, error) {
	basins, err := probeBasins(ctx, embedder, quantizer, probes)
	if err != nil {
		return Attestation{}, err
	}
	attestation := Attestation{
		Version:       AttestationVersion,
		Model:         model,
		Probes:        append([]string(nil), probes...),
		QuantizerSeed: hex.EncodeToString(quantizer.Seed[:]),
	}
	attestation.Digest = hex.EncodeToString(attestationDigest(attestation, basins))
	return attestation, nil
}

// Verify re-runs the probes and refuses if the service no longer matches.
//
// It fails closed in every direction: a malformed attestation, a service that
// errors, a probe set that has become degenerate, and a genuine mismatch are
// all refusals. There is deliberately no "warn and continue" path, because the
// consequence of continuing is a reader quietly fetching a different part of
// the catalogue from everyone else.
func (a Attestation) Verify(ctx context.Context, embedder Embedder, quantizer Quantizer) error {
	if a.Version != AttestationVersion {
		return fmt.Errorf("%w: unrecognised attestation version %q, which is refused "+
			"rather than downgraded", ErrModelChanged, a.Version)
	}
	if hex.EncodeToString(quantizer.Seed[:]) != a.QuantizerSeed {
		return fmt.Errorf("%w: the attestation was recorded under a different quantizer "+
			"seed, so its basins say nothing about this one", ErrModelChanged)
	}
	recorded, err := hex.DecodeString(a.Digest)
	if err != nil || len(recorded) != sha256.Size {
		return fmt.Errorf("%w: malformed attestation digest", ErrModelChanged)
	}
	basins, err := probeBasins(ctx, embedder, quantizer, a.Probes)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(recorded, attestationDigest(a, basins)) != 1 {
		return fmt.Errorf("%w: the service now assigns different basins to the "+
			"attested probes, so every reader on it is fetching a different part of "+
			"the catalogue than readers on the attested model", ErrModelChanged)
	}
	return nil
}

// probeBasins embeds each probe and quantizes it, refusing a probe set that
// could not distinguish one model from another.
func probeBasins(ctx context.Context, embedder Embedder, quantizer Quantizer,
	probes []string) ([]uint64, error) {
	if embedder == nil {
		return nil, errors.New("an embedder is required")
	}
	if len(probes) < MinimumProbes {
		return nil, fmt.Errorf("%w: %d probes, at least %d are required",
			ErrProbeUnusable, len(probes), MinimumProbes)
	}
	seen := map[string]struct{}{}
	for _, probe := range probes {
		if probe == "" {
			return nil, fmt.Errorf("%w: a probe is empty", ErrProbeUnusable)
		}
		if _, repeated := seen[probe]; repeated {
			// A repeated probe adds a row to the digest and no information,
			// so a probe set could look large while fingerprinting little.
			return nil, fmt.Errorf("%w: probe %q appears more than once", ErrProbeUnusable, probe)
		}
		seen[probe] = struct{}{}
	}

	basins := make([]uint64, len(probes))
	for index, probe := range probes {
		vector, err := embedder.Embed(ctx, probe)
		if err != nil {
			return nil, fmt.Errorf("probe %d: %w", index, err)
		}
		basin, err := quantizer.Basin(vector)
		if err != nil {
			return nil, fmt.Errorf("probe %d: %w", index, err)
		}
		basins[index] = basin
	}

	// A service returning one basin for every input matches any attestation
	// built the same way, so such a probe set fingerprints nothing.
	distinct := map[uint64]struct{}{}
	for _, basin := range basins {
		distinct[basin] = struct{}{}
	}
	if len(distinct) < 2 {
		return nil, fmt.Errorf("%w: every probe landed in one basin, so this set "+
			"cannot tell one model from another", ErrProbeUnusable)
	}
	return basins, nil
}

// attestationDigest covers the label, the model, the seed, and each probe
// paired with its basin, all length prefixed so no two different attestations
// produce one digest.
func attestationDigest(a Attestation, basins []uint64) []byte {
	h := sha256.New()
	write := func(field string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(field))
	}
	write(AttestationVersion)
	write(a.Model)
	write(a.QuantizerSeed)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(a.Probes)))
	_, _ = h.Write(count[:])
	for index, probe := range a.Probes {
		write(probe)
		var basin [8]byte
		binary.BigEndian.PutUint64(basin[:], basins[index])
		_, _ = h.Write(basin[:])
	}
	return h.Sum(nil)
}

// DefaultProbes is a fixed, public probe set covering distinct topics, so a
// model change that only affects one subject area still shows up.
//
// It is exported so an operator can see exactly what is sent to their embedding
// service, and so two operators can confirm they attested the same thing. It is
// not secret and must never be replaced with anything derived from a query.
func DefaultProbes() []string {
	probes := []string{
		"a municipal budget hearing scheduled for the following quarter",
		"the migratory range of arctic terns across the north atlantic",
		"a proof that no finite field has order six",
		"instructions for replacing a bicycle's rear derailleur cable",
		"an appellate ruling on the admissibility of hearsay evidence",
		"the fermentation schedule for a sourdough starter in a cold kitchen",
		"changes to the tax treatment of depreciating agricultural equipment",
		"a description of the harmonic series in a plucked string",
	}
	sort.Strings(probes)
	return probes
}
