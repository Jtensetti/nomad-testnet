// Package search ranks verified local objects against a query.
//
// The whole package sits on the private side of the Selection Firewall: it
// sees query text, object bodies and basins, and nothing here is reachable
// from the emission planner. That separation is what makes the timing rule
// below safe to rely on rather than merely intended.
//
// # Why inference latency is a privacy property here
//
// How long an embedder takes depends on the query, on how much text an object
// carries, and on how many candidates matched -- all private state. If that
// latency could reach anything externally observable, it would modulate an
// observable event with private state, which is the one thing Nomad must never
// do. It cannot, because the fabric emits on a fixed cadence that no code in
// this package can reach: a slow embedder costs the reader a wait and costs
// the wire nothing. Budget below therefore exists to protect the reader's
// interface, not the wire; the wire is protected structurally.
package search

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Jtensetti/nomad-semantic-basins/basin"

	"github.com/Jtensetti/nomad-browser/objectstore"
)

// Provenance names the embedder that produced a ranking.
//
// It travels with every result because the two are not interchangeable: a
// lexical ranking presented as a semantic one is a claim the client cannot
// support. There is no default and no unnamed embedder.
type Provenance string

const (
	// ProvenanceLexical is the deterministic bag-of-words baseline. It is a
	// lexical match, not a semantic one, and says so.
	ProvenanceLexical Provenance = "lexical"
)

// Result is one ranked object.
type Result struct {
	Object objectstore.Object
	// Score orders results within one query. It is not comparable across
	// queries or across embedders.
	Score float64
	// Lexical is the number of query tokens the object matched outright.
	Lexical int
	// Provenance names the embedder whose basins produced Semantic.
	Provenance Provenance
	// Semantic is basin agreement in [0,1]. It refines an order; it does not
	// create one, so an object with no lexical match is not returned on the
	// strength of a basin collision alone.
	Semantic float64
}

// Index is the searchable corpus: one basin and one set of weighted token
// sets per object, both built when the object is added.
//
// Objects materialize rarely and queries are interactive, so all of the work
// that depends only on the object happens at materialization. A query then
// costs one embedding call plus set lookups, rather than an inference call and
// a re-tokenization per candidate per keystroke. That is also what makes a
// slow embedder affordable: it is slow once per object, not once per search.
type Index struct {
	embedder    basin.Embedder
	quantizer   basin.Quantizer
	provenance  Provenance
	fingerprint string
	budget      time.Duration

	mutex   sync.RWMutex
	entries map[string]entry
}

// entry is one object reduced to what ranking needs.
type entry struct {
	object objectstore.Object
	basin  uint64
	fields []fieldTokens
}

// fieldTokens is one weighted region of a document. Title matches say more
// about what an object is about than body matches do.
type fieldTokens struct {
	present map[string]struct{}
	weight  int
}

// Config describes an index. Every field is required: an embedder without a
// stated provenance, or with no budget, is a client that cannot say what it
// did or how long it may take doing it.
type Config struct {
	Embedder   basin.Embedder
	Quantizer  basin.Quantizer
	Provenance Provenance
	// Fingerprint identifies what the embedder computes, and it is what an
	// index is stored under.
	//
	// Not the model's name: two installations can hold different weights, a
	// different tokenizer or a different output width under one name, and
	// their vectors are then not comparable at all while every label agrees.
	// basin/model derives one from everything that can move a vector; the
	// lexical baseline has LexicalFingerprint.
	Fingerprint string
	// Budget bounds one embedding call. It is enforced through the context, so
	// an embedder that respects cancellation stops, and one that does not is
	// abandoned rather than waited on.
	Budget time.Duration
}

func New(config Config) (*Index, error) {
	if config.Embedder == nil {
		return nil, errors.New("search index requires an embedder")
	}
	if strings.TrimSpace(string(config.Provenance)) == "" {
		return nil, errors.New("search index requires a named provenance, so a " +
			"ranking can never be presented as something it is not")
	}
	if config.Budget <= 0 {
		return nil, errors.New("search index requires a positive embedding budget")
	}
	if err := ValidFingerprint(config.Fingerprint); err != nil {
		return nil, err
	}
	return &Index{
		embedder:    config.Embedder,
		quantizer:   config.Quantizer,
		provenance:  config.Provenance,
		fingerprint: config.Fingerprint,
		budget:      config.Budget,
		entries:     map[string]entry{},
	}, nil
}

// Provenance names the embedder behind this index.
func (index *Index) Provenance() Provenance { return index.provenance }

// Fingerprint identifies what this index's embedder computes. Two indexes with
// different fingerprints hold vectors that cannot be compared with each other.
func (index *Index) Fingerprint() string { return index.fingerprint }

// Add embeds and tokenizes one object, making it searchable.
//
// A failure leaves the object out of the index rather than storing a zero
// basin, which would rank as a real one and quietly place the object far from
// everything. An object that is not in the index is not searchable, and
// AddAll reports how many those were.
func (index *Index) Add(ctx context.Context, object objectstore.Object) error {
	fields := documentFields(object.Document)
	if len(fields) == 0 {
		return fmt.Errorf("object %s has no indexable text", object.ID)
	}
	value, err := index.basinOf(ctx, indexedText(object))
	if err != nil {
		return fmt.Errorf("embedding object %s: %w", object.ID, err)
	}
	index.mutex.Lock()
	index.entries[object.ID] = entry{object: object, basin: value, fields: fields}
	index.mutex.Unlock()
	return nil
}

// AddAll indexes a whole scan and reports how many objects failed.
//
// One object that will not embed must not stop the rest from being
// searchable, for the same reason one hostile file does not stop a directory
// from loading.
func (index *Index) AddAll(ctx context.Context, objects []objectstore.Object) (indexed, failed int) {
	for _, object := range objects {
		if err := index.Add(ctx, object); err != nil {
			failed++
			continue
		}
		indexed++
	}
	return indexed, failed
}

// Sync makes the index match a directory scan: anything in objects that is not
// already indexed is embedded, and anything indexed that the scan no longer
// contains is dropped.
//
// An object identifier is its content commitment, so an identifier already
// present is the same bytes and is not embedded again. That is what keeps a
// periodic rescan from costing one embedding per object per interval.
func (index *Index) Sync(ctx context.Context, objects []objectstore.Object) (added, failed, removed int) {
	present := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		present[object.ID] = struct{}{}
	}

	index.mutex.Lock()
	known := make(map[string]struct{}, len(index.entries))
	for id := range index.entries {
		known[id] = struct{}{}
		if _, still := present[id]; !still {
			delete(index.entries, id)
			removed++
		}
	}
	index.mutex.Unlock()

	for _, object := range objects {
		if _, already := known[object.ID]; already {
			continue
		}
		if err := index.Add(ctx, object); err != nil {
			failed++
			continue
		}
		added++
	}
	return added, failed, removed
}

// Len reports how many objects are searchable.
func (index *Index) Len() int {
	index.mutex.RLock()
	defer index.mutex.RUnlock()
	return len(index.entries)
}

// Search ranks the indexed corpus against query.
//
// Exactly one embedding call happens per search -- for the query -- because
// everything that depends only on an object was done when it was added. An
// object with no lexical overlap is not returned: basin agreement refines an
// order that lexical matching established, so a basin collision on its own
// cannot surface an unrelated object.
func (index *Index) Search(ctx context.Context, query string) ([]Result, error) {
	queryTokens := unique(tokens(query))
	if len(queryTokens) == 0 {
		return nil, nil
	}
	queryBasin, err := index.basinOf(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("embedding the query: %w", err)
	}

	index.mutex.RLock()
	defer index.mutex.RUnlock()

	results := make([]Result, 0, len(index.entries))
	for _, indexed := range index.entries {
		lexical := indexed.overlap(queryTokens)
		if lexical == 0 {
			continue
		}
		semantic := agreement(queryBasin, indexed.basin)
		results = append(results, Result{
			Object:     indexed.object,
			Score:      float64(lexical) + semantic,
			Lexical:    lexical,
			Provenance: index.provenance,
			Semantic:   semantic,
		})
	}
	// Map iteration is unordered, so the tiebreak carries the whole ordering
	// for equal scores. Without it the same query would return the same
	// results in a different order each run.
	sort.Slice(results, func(a, b int) bool {
		if results[a].Score != results[b].Score {
			return results[a].Score > results[b].Score
		}
		if results[a].Object.Document.Title != results[b].Object.Document.Title {
			return results[a].Object.Document.Title < results[b].Object.Document.Title
		}
		return results[a].Object.ID < results[b].Object.ID
	})
	return results, nil
}

func (index *Index) basinOf(ctx context.Context, text string) (uint64, error) {
	bounded, cancel := context.WithTimeout(ctx, index.budget)
	defer cancel()
	vector, err := index.embedder.Embed(bounded, text)
	if err != nil {
		return 0, err
	}
	return index.quantizer.Basin(vector)
}

// agreement is basin agreement in [0,1]: the fraction of the 64 basin bits two
// values share.
func agreement(a, b uint64) float64 {
	return float64(64-bits.OnesCount64(a^b)) / 64
}

// indexedText is what an object contributes to its basin. Body is bounded so
// one long object cannot dominate the embedder's input budget.
func indexedText(object objectstore.Object) string {
	document := object.Document
	return strings.Join([]string{
		document.Title,
		strings.Join(document.Tags, " "),
		document.Summary,
		truncate(document.Body, MaxIndexedBodyBytes),
	}, "\n")
}

// documentFields reduces a document to the weighted token sets ranking needs.
// It returns nothing for a document with no tokens anywhere, which is not
// searchable and is kept out of the index rather than stored as a dead entry.
func documentFields(document objectstore.Document) []fieldTokens {
	fields := make([]fieldTokens, 0, 4)
	for _, region := range []struct {
		text   string
		weight int
	}{
		{document.Title, 8},
		{strings.Join(document.Tags, " "), 5},
		{document.Summary, 3},
		{truncate(document.Body, MaxIndexedBodyBytes), 1},
	} {
		words := tokens(region.text)
		if len(words) == 0 {
			continue
		}
		present := make(map[string]struct{}, len(words))
		for _, word := range words {
			present[word] = struct{}{}
		}
		fields = append(fields, fieldTokens{present: present, weight: region.weight})
	}
	return fields
}

// truncate cuts text to at most limit bytes without splitting a rune.
func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}

// MaxIndexedBodyBytes bounds how much of one object's body reaches the
// embedder, so indexing cost stays proportional to the number of objects
// rather than to the largest one.
const MaxIndexedBodyBytes = 32 << 10

// tokens splits text into lowercase alphanumeric tokens of at least two
// runes. Single-rune tokens match too much to be worth an index entry.
func tokens(text string) []string {
	fields := strings.FieldsFunc(strings.ToLower(truncate(text, MaxIndexedBodyBytes)),
		func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
	out := fields[:0]
	for _, field := range fields {
		if utf8.RuneCountInString(field) >= 2 {
			out = append(out, field)
		}
	}
	return out
}

// overlap scores one object against already-uniqued query tokens, using only
// the sets built when the object was added.
func (e entry) overlap(queryTokens []string) int {
	total := 0
	for _, field := range e.fields {
		matched := 0
		for _, token := range queryTokens {
			if _, ok := field.present[token]; ok {
				matched++
			}
		}
		total += matched * field.weight
	}
	return total
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
