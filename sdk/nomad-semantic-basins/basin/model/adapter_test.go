package model

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// fixedRuntime returns a vector derived from the text, so a change in what the
// adapter prepends is visible in the output.
type fixedRuntime struct {
	width int
	calls []string
}

func (r *fixedRuntime) Infer(_ context.Context, text string) ([]float32, error) {
	r.calls = append(r.calls, text)
	vector := make([]float32, r.width)
	for index := range vector {
		vector[index] = float32(len(text)+index) / 100
	}
	return vector, nil
}

type hangingRuntime struct{}

func (hangingRuntime) Infer(ctx context.Context, _ string) ([]float32, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type widthRuntime struct{ width int }

func (w widthRuntime) Infer(context.Context, string) ([]float32, error) {
	return make([]float32, w.width), nil
}

type valueRuntime struct{ values []float32 }

func (v valueRuntime) Infer(context.Context, string) ([]float32, error) {
	return append([]float32(nil), v.values...), nil
}

func gemmaEmbedder(t *testing.T, runtime Runtime) *SemanticEmbedder {
	t.Helper()
	embedder, err := New(Config{
		Manifest: validManifest(),
		Adapter:  GemmaAdapter{},
		Runtime:  runtime,
		Budget:   2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return embedder
}

// The prefixes are pinned literally.
//
// A change to one of them changes every vector an adapter has ever produced
// while leaving the weights, the tokenizer and the output shape untouched. The
// vectors stay well-formed, normalized and the right width; only the ranking
// gets quietly worse, and nothing downstream can see it. So the literals are
// asserted here, and the adapter version must move with them -- which is what
// puts the change into the fingerprint and forces a reindex.
func TestTheAdapterConventionsArePinnedToTheirVersions(t *testing.T) {
	for _, testcase := range []struct {
		adapter  Adapter
		version  int
		query    string
		document string
	}{
		{GemmaAdapter{}, 1,
			"task: search result | query: hej", "title: none | text: hej"},
		{E5Adapter{}, 1,
			"query: hej", "passage: hej"},
		{QwenAdapter{Instruction: "Find it"}, 1,
			"Instruct: Find it\nQuery: hej", "hej"},
		{PlainAdapter{}, 1, "hej", "hej"},
	} {
		t.Run(testcase.adapter.Name(), func(t *testing.T) {
			if got := testcase.adapter.Version(); got != testcase.version {
				t.Fatalf("version is %d, want %d; if the conventions below changed "+
					"deliberately, this number moves with them and every index built "+
					"on the old ones is no longer comparable", got, testcase.version)
			}
			if got := testcase.adapter.QueryText("hej"); got != testcase.query {
				t.Errorf("query text is %q, want %q", got, testcase.query)
			}
			if got := testcase.adapter.DocumentText("hej"); got != testcase.document {
				t.Errorf("document text is %q, want %q", got, testcase.document)
			}
		})
	}
}

// A query and a document are not interchangeable, and the difference must reach
// the runtime rather than stopping at the adapter.
func TestAQueryAndADocumentReachTheRuntimeDifferently(t *testing.T) {
	runtime := &fixedRuntime{width: 768}
	embedder := gemmaEmbedder(t, runtime)
	ctx := context.Background()

	if _, err := embedder.EmbedQuery(ctx, "nomad"); err != nil {
		t.Fatal(err)
	}
	if _, err := embedder.EmbedDocument(ctx, "nomad"); err != nil {
		t.Fatal(err)
	}
	if len(runtime.calls) != 2 {
		t.Fatalf("the runtime saw %d calls", len(runtime.calls))
	}
	if runtime.calls[0] == runtime.calls[1] {
		t.Fatalf("the query and the document reached the runtime as the same text %q, "+
			"so the family's conventions were not applied", runtime.calls[0])
	}
	if !strings.Contains(runtime.calls[0], "nomad") || !strings.Contains(runtime.calls[1], "nomad") {
		t.Fatal("the adapter dropped the caller's text")
	}
}

// The manifest is what the fingerprint describes, so an adapter that is not
// the one it names must not run at all.
func TestAnAdapterThatTheManifestDoesNotNameIsRefused(t *testing.T) {
	manifest := validManifest() // names gemma, version 1
	for _, testcase := range []struct {
		name    string
		adapter Adapter
	}{
		{"a different family", E5Adapter{}},
		{"a different version", bumpedGemma{}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := New(Config{
				Manifest: manifest, Adapter: testcase.adapter,
				Runtime: &fixedRuntime{width: 768}, Budget: time.Second,
			})
			if err == nil {
				t.Fatal("an embedder was built whose fingerprint describes an adapter " +
					"other than the one that would run")
			}
		})
	}
}

type bumpedGemma struct{ GemmaAdapter }

func (bumpedGemma) Version() int { return 2 }

// An unknown adapter is an error, never a silent fall back to no conventions.
func TestAnUnknownAdapterIsRefusedRatherThanRunPlain(t *testing.T) {
	manifest := validManifest()
	manifest.Adapter = "some-future-family"
	if _, err := BuiltinAdapter(manifest); err == nil {
		t.Fatal("an unknown family resolved to an adapter; running an E5 model with " +
			"no prefixes produces well-formed vectors and worse retrieval, with " +
			"nothing to indicate it")
	}
	for _, known := range []string{"gemma", "e5", "qwen", "plain"} {
		manifest.Adapter = known
		if _, err := BuiltinAdapter(manifest); err != nil {
			t.Errorf("%s: %v", known, err)
		}
	}
}

// Matryoshka truncation narrows the vector and renormalizes it, because
// truncating changes the norm and an unnormalized tail would scale every
// distance by how much was discarded.
func TestTruncationNarrowsAndRenormalizes(t *testing.T) {
	runtime := &fixedRuntime{width: 768}
	embedder := gemmaEmbedder(t, runtime)

	vector, err := embedder.EmbedQuery(context.Background(), "nomad")
	if err != nil {
		t.Fatal(err)
	}
	if len(vector) != 256 {
		t.Fatalf("got %d dimensions, the manifest configures 256", len(vector))
	}
	if got := embedder.Dimensions(); got != 256 {
		t.Fatalf("Dimensions reports %d", got)
	}
	var sum float64
	for _, value := range vector {
		sum += float64(value) * float64(value)
	}
	if math.Abs(math.Sqrt(sum)-1) > 1e-6 {
		t.Fatalf("the truncated vector has norm %v, want 1", math.Sqrt(sum))
	}
}

// A runtime whose width is not the declared one means the loaded pack is not
// the pack the manifest describes, so every vector it produced would carry the
// wrong fingerprint.
func TestARuntimeOfTheWrongWidthIsRefused(t *testing.T) {
	embedder := gemmaEmbedder(t, widthRuntime{width: 384})
	if _, err := embedder.EmbedQuery(context.Background(), "nomad"); err == nil {
		t.Fatal("a runtime emitting 384 dimensions was accepted under a manifest " +
			"declaring 768")
	}
}

// A non-finite value would quantize into a basin and rank against real ones.
func TestANonFiniteValueIsRefused(t *testing.T) {
	for _, bad := range []float32{
		float32(math.NaN()),
		float32(math.Inf(1)),
		float32(math.Inf(-1)),
	} {
		values := make([]float32, 768)
		values[7] = bad
		embedder := gemmaEmbedder(t, valueRuntime{values: values})
		if _, err := embedder.EmbedQuery(context.Background(), "nomad"); err == nil {
			t.Fatalf("a vector containing %v was accepted", bad)
		}
	}
}

// A zero vector has no direction, so normalizing it cannot produce one.
func TestAZeroVectorIsRefusedRatherThanNormalized(t *testing.T) {
	embedder := gemmaEmbedder(t, valueRuntime{values: make([]float32, 768)})
	if _, err := embedder.EmbedQuery(context.Background(), "nomad"); err == nil {
		t.Fatal("a zero vector was accepted and normalized into something")
	}
}

// A model that will not return is abandoned at its budget. The reader waits for
// the budget, never for the model.
func TestAHangingRuntimeIsAbandonedAtItsBudget(t *testing.T) {
	embedder, err := New(Config{
		Manifest: validManifest(), Adapter: GemmaAdapter{},
		Runtime: hangingRuntime{}, Budget: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = embedder.EmbedQuery(context.Background(), "nomad")
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want a deadline error", err)
	}
	if elapsed > time.Second {
		t.Fatalf("the budget took %v to take effect", elapsed)
	}
}

// An embedder cannot be built without a budget, and an unbounded one is the
// default this refuses to have.
func TestAnEmbedderCannotBeBuiltWithoutABudget(t *testing.T) {
	for _, budget := range []time.Duration{0, -time.Second} {
		_, err := New(Config{
			Manifest: validManifest(), Adapter: GemmaAdapter{},
			Runtime: &fixedRuntime{width: 768}, Budget: budget,
		})
		if err == nil {
			t.Fatalf("an embedder was built with budget %v", budget)
		}
	}
}

// Empty text has no embedding, and a runtime should never be asked for one.
func TestEmptyTextIsRefusedBeforeTheRuntime(t *testing.T) {
	runtime := &fixedRuntime{width: 768}
	embedder := gemmaEmbedder(t, runtime)
	for _, text := range []string{"", "   ", "\t\n"} {
		if _, err := embedder.EmbedQuery(context.Background(), text); err == nil {
			t.Fatalf("%q was embedded", text)
		}
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("the runtime was called %d times for empty text", len(runtime.calls))
	}
}
