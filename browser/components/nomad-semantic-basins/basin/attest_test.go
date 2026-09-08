package basin

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func testQuantizer(seed byte) Quantizer {
	var q Quantizer
	for i := range q.Seed {
		q.Seed[i] = seed
	}
	return q
}

func testEmbedder() Embedder { return LexicalHashEmbedder{Dims: 128} }

// driftingEmbedder is a model that has changed: it perturbs the text before
// embedding it, which is what a swapped or retrained model does to basins from
// the caller's point of view.
type driftingEmbedder struct {
	inner  Embedder
	suffix string
}

func (d driftingEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	return d.inner.Embed(ctx, text+" "+d.suffix)
}

// constantEmbedder returns one vector whatever it is asked. A service like this
// matches any attestation built against a probe set that cannot tell inputs
// apart, which is the reason probeBasins refuses such a set.
type constantEmbedder struct{ inner Embedder }

func (c constantEmbedder) Embed(ctx context.Context, _ string) ([]float32, error) {
	return c.inner.Embed(ctx, "always the same answer")
}

type failingEmbedder struct{}

func (failingEmbedder) Embed(context.Context, string) ([]float32, error) {
	return nil, errors.New("the embedding service is down")
}

func TestAnUnchangedServiceVerifiesAgainstItsAttestation(t *testing.T) {
	ctx := context.Background()
	quantizer := testQuantizer(7)
	embedder := testEmbedder()

	attestation, err := Attest(ctx, embedder, quantizer, "test-model-v1", DefaultProbes())
	if err != nil {
		t.Fatal(err)
	}
	if attestation.Version != AttestationVersion || attestation.Digest == "" {
		t.Fatalf("attestation is incomplete: %+v", attestation)
	}
	if err := attestation.Verify(ctx, embedder, quantizer); err != nil {
		t.Fatalf("an unchanged service failed its own attestation: %v", err)
	}
	// And it is reproducible: attesting twice must produce one digest, or the
	// artefact could not be published or compared between operators.
	again, err := Attest(ctx, embedder, quantizer, "test-model-v1", DefaultProbes())
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest != attestation.Digest {
		t.Fatalf("two attestations of one service differ: %s and %s",
			attestation.Digest, again.Digest)
	}
}

// The claim that matters: a model that has changed is caught.
func TestAChangedModelFailsVerification(t *testing.T) {
	ctx := context.Background()
	quantizer := testQuantizer(7)
	attestation, err := Attest(ctx, testEmbedder(), quantizer, "test-model-v1", DefaultProbes())
	if err != nil {
		t.Fatal(err)
	}

	drifted := driftingEmbedder{inner: testEmbedder(), suffix: "retrained"}
	// Establish that the drifted model really does move basins, or the case
	// below would pass for the wrong reason.
	moved := 0
	for _, probe := range attestation.Probes {
		before, err := testEmbedder().Embed(ctx, probe)
		if err != nil {
			t.Fatal(err)
		}
		after, err := drifted.Embed(ctx, probe)
		if err != nil {
			t.Fatal(err)
		}
		basinBefore, err := quantizer.Basin(before)
		if err != nil {
			t.Fatal(err)
		}
		basinAfter, err := quantizer.Basin(after)
		if err != nil {
			t.Fatal(err)
		}
		if basinBefore != basinAfter {
			moved++
		}
	}
	if moved == 0 {
		t.Fatal("the drifted model moves no basin, so this case tests nothing")
	}
	t.Logf("the drifted model moves %d of %d probe basins", moved, len(attestation.Probes))

	if err := attestation.Verify(ctx, drifted, quantizer); !errors.Is(err, ErrModelChanged) {
		t.Fatalf("a changed model passed verification: %v", err)
	}
}

// An attestation is meaningless without the quantizer that produced it, so
// verifying under a different seed must be refused rather than silently
// compared.
func TestAnAttestationDoesNotTransferAcrossQuantizerSeeds(t *testing.T) {
	ctx := context.Background()
	attestation, err := Attest(ctx, testEmbedder(), testQuantizer(7), "test-model-v1", DefaultProbes())
	if err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(ctx, testEmbedder(), testQuantizer(9)); !errors.Is(err, ErrModelChanged) {
		t.Fatalf("an attestation verified under a different quantizer seed: %v", err)
	}
}

// Everything about verification fails closed.
func TestVerificationFailsClosed(t *testing.T) {
	ctx := context.Background()
	quantizer := testQuantizer(7)
	valid, err := Attest(ctx, testEmbedder(), quantizer, "test-model-v1", DefaultProbes())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unknown attestation version", func(t *testing.T) {
		tampered := valid
		tampered.Version = "nomad-basin-model-attestation-v2"
		if err := tampered.Verify(ctx, testEmbedder(), quantizer); !errors.Is(err, ErrModelChanged) {
			t.Fatalf("an unrecognised version was accepted: %v", err)
		}
	})

	t.Run("malformed digest", func(t *testing.T) {
		tampered := valid
		tampered.Digest = "not hex"
		if err := tampered.Verify(ctx, testEmbedder(), quantizer); !errors.Is(err, ErrModelChanged) {
			t.Fatalf("a malformed digest was accepted: %v", err)
		}
	})

	t.Run("a probe was edited", func(t *testing.T) {
		tampered := valid
		tampered.Probes = append([]string(nil), valid.Probes...)
		tampered.Probes[0] = tampered.Probes[0] + " altered"
		if err := tampered.Verify(ctx, testEmbedder(), quantizer); !errors.Is(err, ErrModelChanged) {
			t.Fatalf("an edited probe set was accepted: %v", err)
		}
	})

	t.Run("probes reordered", func(t *testing.T) {
		tampered := valid
		tampered.Probes = append([]string(nil), valid.Probes...)
		tampered.Probes[0], tampered.Probes[1] = tampered.Probes[1], tampered.Probes[0]
		if err := tampered.Verify(ctx, testEmbedder(), quantizer); !errors.Is(err, ErrModelChanged) {
			t.Fatalf("a reordered probe set was accepted, so the digest does not bind order: %v", err)
		}
	})

	t.Run("the service is down", func(t *testing.T) {
		if err := valid.Verify(ctx, failingEmbedder{}, quantizer); err == nil {
			t.Fatal("a service that cannot answer was treated as verified")
		}
	})

	t.Run("no embedder at all", func(t *testing.T) {
		if err := valid.Verify(ctx, nil, quantizer); err == nil {
			t.Fatal("a nil embedder was treated as verified")
		}
	})
}

// A probe set that cannot distinguish models must be refused when the
// attestation is made, not discovered later when it silently matches
// everything.
func TestADegenerateProbeSetIsRefused(t *testing.T) {
	ctx := context.Background()
	quantizer := testQuantizer(7)

	t.Run("too few probes", func(t *testing.T) {
		if _, err := Attest(ctx, testEmbedder(), quantizer, "m",
			[]string{"one", "two"}); !errors.Is(err, ErrProbeUnusable) {
			t.Fatalf("a two-probe set was accepted: %v", err)
		}
	})

	t.Run("repeated probe", func(t *testing.T) {
		repeated := []string{"alpha", "beta", "gamma", "alpha"}
		if _, err := Attest(ctx, testEmbedder(), quantizer, "m",
			repeated); !errors.Is(err, ErrProbeUnusable) {
			t.Fatalf("a probe set with a repeat was accepted: %v", err)
		}
	})

	t.Run("empty probe", func(t *testing.T) {
		if _, err := Attest(ctx, testEmbedder(), quantizer, "m",
			[]string{"alpha", "", "gamma", "delta"}); !errors.Is(err, ErrProbeUnusable) {
			t.Fatalf("a probe set containing an empty string was accepted: %v", err)
		}
	})

	t.Run("a service that answers everything the same", func(t *testing.T) {
		// Every probe lands in one basin, so the fingerprint would match any
		// other constant service.
		if _, err := Attest(ctx, constantEmbedder{inner: testEmbedder()}, quantizer, "m",
			DefaultProbes()); !errors.Is(err, ErrProbeUnusable) {
			t.Fatalf("a constant service produced a usable attestation: %v", err)
		}
	})
}

// The probe set is published, so it must be fixed public text and must not
// look like anything a reader typed.
func TestTheDefaultProbeSetIsFixedAndUsable(t *testing.T) {
	first := DefaultProbes()
	second := DefaultProbes()
	if len(first) < MinimumProbes {
		t.Fatalf("the default probe set has %d probes, fewer than the %d minimum",
			len(first), MinimumProbes)
	}
	for index := range first {
		if first[index] != second[index] {
			t.Fatal("DefaultProbes is not stable between calls")
		}
	}
	// Mutating what a caller received must not change what the next caller
	// gets, or one component could quietly reshape a published artefact.
	first[0] = "mutated"
	if DefaultProbes()[0] == "mutated" {
		t.Fatal("DefaultProbes returns shared state a caller can mutate")
	}

	seen := map[string]struct{}{}
	for _, probe := range second {
		if strings.TrimSpace(probe) == "" {
			t.Fatal("a default probe is blank")
		}
		if _, repeated := seen[probe]; repeated {
			t.Fatalf("the default probe set repeats %q", probe)
		}
		seen[probe] = struct{}{}
	}

	// And it must actually fingerprint: distinct basins under a real quantizer.
	attestation, err := Attest(context.Background(), testEmbedder(), testQuantizer(3), "m", second)
	if err != nil {
		t.Fatalf("the default probe set cannot attest anything: %v", err)
	}
	if attestation.Digest == "" {
		t.Fatal("the default probe set produced an empty digest")
	}
}

// An attestation is a published artefact, so nothing in it may vary with what
// a reader is doing. The strongest available check is that the whole thing is a
// function of its declared inputs: same embedder, same quantizer, same probes,
// same bytes, no matter what else the process has done.
func TestAnAttestationIsAFunctionOfItsDeclaredInputsAlone(t *testing.T) {
	ctx := context.Background()
	quantizer := testQuantizer(7)
	embedder := testEmbedder()

	baseline, err := Attest(ctx, embedder, quantizer, "test-model-v1", DefaultProbes())
	if err != nil {
		t.Fatal(err)
	}

	// Embed a pile of unrelated "reader activity" between attestations. If any
	// of it reached the artefact, the digest would move.
	for _, query := range []string{
		"where can I find the leaked documents",
		"how to contact a lawyer anonymously",
		"local protest schedule",
	} {
		if _, err := embedder.Embed(ctx, query); err != nil {
			t.Fatal(err)
		}
		if _, err := quantizer.Basin(mustEmbed(t, embedder, query)); err != nil {
			t.Fatal(err)
		}
	}

	after, err := Attest(ctx, embedder, quantizer, "test-model-v1", DefaultProbes())
	if err != nil {
		t.Fatal(err)
	}
	if after.Digest != baseline.Digest {
		t.Fatal("an attestation changed after unrelated queries were embedded, so it " +
			"carries something other than its declared inputs")
	}
}

func mustEmbed(t *testing.T, embedder Embedder, text string) []float32 {
	t.Helper()
	vector, err := embedder.Embed(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	return vector
}
