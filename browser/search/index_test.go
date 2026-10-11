package search

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-semantic-basins/basin"

	"github.com/Jtensetti/nomad-browser/objectstore"
)

// countingEmbedder wraps the lexical baseline and counts calls, so the tests
// can assert how much model work a search costs rather than assuming.
type countingEmbedder struct {
	inner basin.Embedder
	calls atomic.Int64
}

func (c *countingEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	c.calls.Add(1)
	return c.inner.Embed(ctx, text)
}

// hangingEmbedder never returns on its own. It stands in for a model that is
// loading, swapping or simply slower than its budget.
type hangingEmbedder struct{}

func (hangingEmbedder) Embed(ctx context.Context, _ string) ([]float32, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type failingEmbedder struct{}

var errNoModel = errors.New("no model")

func (failingEmbedder) Embed(context.Context, string) ([]float32, error) { return nil, errNoModel }

func testIndex(t *testing.T, embedder basin.Embedder) *Index {
	t.Helper()
	index, err := New(Config{
		Embedder:    embedder,
		Quantizer:   basin.Quantizer{Seed: [32]byte{7}},
		Provenance:  ProvenanceLexical,
		Fingerprint: LexicalFingerprint(128),
		Budget:      2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func lexical() basin.Embedder {
	return basin.LexicalHashEmbedder{Dims: 128}
}

func object(id, title, summary, body string, tags ...string) objectstore.Object {
	return objectstore.Object{
		ID: id,
		Document: objectstore.Document{
			Title: title, Summary: summary, Body: body, Tags: tags,
			MediaType: objectstore.RenderableMediaType,
		},
	}
}

func TestATitleMatchOutranksABodyMatch(t *testing.T) {
	index := testIndex(t, lexical())
	ctx := context.Background()
	if _, failed := index.AddAll(ctx, []objectstore.Object{
		object("a", "Kryptografi i praktiken", "", "helt annat innehall"),
		object("b", "Nagot annat", "", "en text som namner kryptografi en gang"),
	}); failed != 0 {
		t.Fatalf("%d objects failed to index", failed)
	}
	results, err := index.Search(ctx, "kryptografi")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Object.ID != "a" {
		t.Fatalf("body match outranked title match: %+v", results)
	}
}

// The load-bearing performance claim: a search costs one embedding call, no
// matter how large the corpus is. Everything else was done when the objects
// were added. If this ever became one call per candidate, a real model would
// make every keystroke unusable.
func TestASearchCostsExactlyOneEmbeddingCall(t *testing.T) {
	counter := &countingEmbedder{inner: lexical()}
	index := testIndex(t, counter)
	ctx := context.Background()

	objects := make([]objectstore.Object, 64)
	for i := range objects {
		objects[i] = object(string(rune('a'+i%26))+string(rune('a'+i/26)),
			"Titel om nomad", "sammanfattning", "brodtext om nomad och natverk")
	}
	if indexed, failed := index.AddAll(ctx, objects); failed != 0 || indexed == 0 {
		t.Fatalf("indexed %d, failed %d", indexed, failed)
	}
	afterIndexing := counter.calls.Load()

	if _, err := index.Search(ctx, "nomad"); err != nil {
		t.Fatal(err)
	}
	if searchCalls := counter.calls.Load() - afterIndexing; searchCalls != 1 {
		t.Fatalf("one search made %d embedding calls; the per-object work has "+
			"moved back into the query path", searchCalls)
	}
}

// An embedder that does not return is abandoned at its budget. A reader waits
// for the budget, never for the model.
func TestAHangingEmbedderIsAbandonedAtItsBudget(t *testing.T) {
	index, err := New(Config{
		Embedder:    hangingEmbedder{},
		Quantizer:   basin.Quantizer{Seed: [32]byte{7}},
		Provenance:  ProvenanceLexical,
		Fingerprint: LexicalFingerprint(128),
		Budget:      50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	addErr := index.Add(context.Background(), object("a", "Titel", "", "brodtext"))
	elapsed := time.Since(start)
	if addErr == nil {
		t.Fatal("a hanging embedder returned successfully")
	}
	if !errors.Is(addErr, context.DeadlineExceeded) {
		t.Fatalf("got %v, want a deadline error", addErr)
	}
	if elapsed > time.Second {
		t.Fatalf("the budget took %v to take effect", elapsed)
	}
}

// An object that will not embed is left out of the index and counted. It is
// not stored with a zero basin, which would rank as a real one.
func TestAnObjectThatWillNotEmbedIsLeftOutAndCounted(t *testing.T) {
	index := testIndex(t, failingEmbedder{})
	indexed, failed := index.AddAll(context.Background(), []objectstore.Object{
		object("a", "Titel", "", "brodtext"),
		object("b", "Annan", "", "brodtext"),
	})
	if indexed != 0 || failed != 2 {
		t.Fatalf("indexed %d failed %d, want 0 and 2", indexed, failed)
	}
	if index.Len() != 0 {
		t.Fatalf("index holds %d entries after every add failed", index.Len())
	}
}

// Every result names the embedder that produced it, so a lexical ranking can
// never be presented as a semantic one.
func TestEveryResultCarriesItsProvenance(t *testing.T) {
	index := testIndex(t, lexical())
	ctx := context.Background()
	if err := index.Add(ctx, object("a", "Nomad", "", "brodtext om nomad")); err != nil {
		t.Fatal(err)
	}
	results, err := index.Search(ctx, "nomad")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, result := range results {
		if result.Provenance != ProvenanceLexical {
			t.Fatalf("result carries provenance %q", result.Provenance)
		}
	}
}

// An index cannot be built without a stated provenance or a budget. Both
// defaults would be silent: an unnamed embedder, or an unbounded one.
func TestAnIndexCannotBeBuiltWithoutProvenanceBudgetOrFingerprint(t *testing.T) {
	for _, testcase := range []struct {
		name   string
		config Config
	}{
		{"no embedder", Config{Provenance: ProvenanceLexical,
			Fingerprint: LexicalFingerprint(128), Budget: time.Second}},
		{"no provenance", Config{Embedder: lexical(),
			Fingerprint: LexicalFingerprint(128), Budget: time.Second}},
		{"blank provenance", Config{Embedder: lexical(), Provenance: "  ",
			Fingerprint: LexicalFingerprint(128), Budget: time.Second}},
		{"no budget", Config{Embedder: lexical(), Provenance: ProvenanceLexical,
			Fingerprint: LexicalFingerprint(128)}},
		{"no fingerprint", Config{Embedder: lexical(), Provenance: ProvenanceLexical,
			Budget: time.Second}},
		{"a fingerprint that is not hex", Config{Embedder: lexical(),
			Provenance: ProvenanceLexical, Budget: time.Second,
			Fingerprint: "../../etc/passwd"}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			if _, err := New(testcase.config); err == nil {
				t.Fatal("an index was built without it")
			}
		})
	}
}

// A basin collision alone must not surface an object the query does not match.
func TestBasinAgreementAloneDoesNotSurfaceAnObject(t *testing.T) {
	index := testIndex(t, lexical())
	ctx := context.Background()
	if err := index.Add(ctx, object("a", "Helt orelaterat", "", "ingenting gemensamt")); err != nil {
		t.Fatal(err)
	}
	results, err := index.Search(ctx, "kryptografi")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("an object with no lexical match was returned: %+v", results)
	}
}

// The corpus lives in a map, so without an explicit tiebreak the same query
// would return the same results in a different order on every run.
func TestEqualScoresOrderDeterministically(t *testing.T) {
	ctx := context.Background()
	first, err := rankTitles(ctx, t)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 8; attempt++ {
		again, err := rankTitles(ctx, t)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(again, ",") != strings.Join(first, ",") {
			t.Fatalf("attempt %d ordered results differently:\n %v\n %v", attempt, again, first)
		}
	}
}

func rankTitles(ctx context.Context, t *testing.T) ([]string, error) {
	t.Helper()
	index := testIndex(t, lexical())
	for _, title := range []string{"Alfa", "Beta", "Gamma", "Delta", "Epsilon"} {
		if err := index.Add(ctx, object(title, title+" nomad", "", "samma brodtext nomad")); err != nil {
			return nil, err
		}
	}
	results, err := index.Search(ctx, "nomad")
	if err != nil {
		return nil, err
	}
	titles := make([]string, 0, len(results))
	for _, result := range results {
		titles = append(titles, result.Object.Document.Title)
	}
	return titles, nil
}
