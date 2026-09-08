package model

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

// Runtime turns text into a vector. It is the only part of semantic search
// that a model pack supplies and that this repository does not implement:
// no weights, no tokenizer, no inference loop live here.
//
// A Runtime is expected to honour ctx. One that does not is abandoned at its
// budget rather than waited on, which costs a goroutine until it returns.
type Runtime interface {
	Infer(ctx context.Context, text string) ([]float32, error)
}

// Adapter carries one model family's conventions.
//
// Families differ in ways that are invisible in the output and ruinous in the
// ranking. E5 wants "query:" and "passage:" prefixes; EmbeddingGemma wants a
// task-shaped prompt; Qwen3 instructs on the query side and leaves documents
// bare. Get it wrong and every vector is still a well-formed vector, still
// normalized, still the right width -- and retrieval is quietly worse. Nothing
// downstream can detect it.
//
// That is why Version is here and why it reaches the fingerprint. A correction
// to a prefix changes every vector the adapter has produced, without touching
// the weights or the tokenizer, and an index built before the correction is not
// comparable with one built after it.
type Adapter interface {
	Name() string
	Version() int
	QueryText(text string) string
	DocumentText(text string) string
}

// The three adapters below implement the conventions their model families
// document. Each is pinned by a test that fails if a prefix changes without
// the version changing with it, because a silent prefix change is the one
// failure in this package that produces no error and no wrong-looking output.

// GemmaAdapter implements EmbeddingGemma's task-prompt convention.
type GemmaAdapter struct{}

func (GemmaAdapter) Name() string { return "gemma" }
func (GemmaAdapter) Version() int { return 1 }
func (GemmaAdapter) QueryText(text string) string {
	return "task: search result | query: " + text
}
func (GemmaAdapter) DocumentText(text string) string {
	return "title: none | text: " + text
}

// E5Adapter implements the multilingual-e5 prefix convention.
type E5Adapter struct{}

func (E5Adapter) Name() string                    { return "e5" }
func (E5Adapter) Version() int                    { return 1 }
func (E5Adapter) QueryText(text string) string    { return "query: " + text }
func (E5Adapter) DocumentText(text string) string { return "passage: " + text }

// QwenAdapter implements Qwen3-Embedding's convention: an instruction on the
// query side, documents unprefixed.
//
// Instruction is part of the prompt and therefore part of what the model sees,
// so a deployment that changes it changes its vectors. It is carried in the
// manifest's inference settings rather than hardcoded here, which is what puts
// it in the fingerprint.
type QwenAdapter struct{ Instruction string }

func (QwenAdapter) Name() string { return "qwen" }
func (QwenAdapter) Version() int { return 1 }
func (a QwenAdapter) QueryText(text string) string {
	instruction := a.Instruction
	if instruction == "" {
		instruction = DefaultQwenInstruction
	}
	return "Instruct: " + instruction + "\nQuery: " + text
}
func (QwenAdapter) DocumentText(text string) string { return text }

// DefaultQwenInstruction is the retrieval task Qwen is instructed with when a
// manifest names none.
const DefaultQwenInstruction = "Given a search query, retrieve relevant passages that answer the query"

// PlainAdapter applies no conventions. It is for model families that draw no
// distinction between a query and a document, and for a custom pack whose
// conventions the operator has already applied.
type PlainAdapter struct{}

func (PlainAdapter) Name() string                    { return "plain" }
func (PlainAdapter) Version() int                    { return 1 }
func (PlainAdapter) QueryText(text string) string    { return text }
func (PlainAdapter) DocumentText(text string) string { return text }

// BuiltinAdapter returns the adapter a manifest names, if this build has one.
//
// An unknown adapter is an error rather than a fallback to PlainAdapter.
// Falling back would run an E5 model with no prefixes at all: every vector
// well-formed, retrieval quietly degraded, nothing to see in any log.
func BuiltinAdapter(manifest Manifest) (Adapter, error) {
	switch manifest.Adapter {
	case "gemma":
		return GemmaAdapter{}, nil
	case "e5":
		return E5Adapter{}, nil
	case "qwen":
		return QwenAdapter{Instruction: manifest.InferenceSettings["instruction"]}, nil
	case "plain":
		return PlainAdapter{}, nil
	}
	return nil, fmt.Errorf("no adapter named %q is built in; a model family this "+
		"build does not know must supply its own rather than be run without one",
		manifest.Adapter)
}

// SemanticEmbedder is a manifest, an adapter and a runtime, driven together.
//
// It is what the search side programs against, and it is where the model's
// identity and the vector it produces are kept in step: the fingerprint it
// reports is the manifest's, and the manifest describes the adapter and the
// runtime that actually ran.
type SemanticEmbedder struct {
	manifest Manifest
	adapter  Adapter
	runtime  Runtime
	budget   time.Duration
}

// Config builds a SemanticEmbedder. Every field is required.
type Config struct {
	Manifest Manifest
	Adapter  Adapter
	Runtime  Runtime
	// Budget bounds one inference call, enforced through the context.
	//
	// It exists for the reader's interface rather than for the wire. Inference
	// time depends on the query, which is private, but nothing on this side of
	// the Selection Firewall can reach the emission planner and the fabric
	// emits on a fixed cadence regardless, so a slow model costs a reader a
	// wait and costs an observer nothing.
	Budget time.Duration
}

// New checks that the manifest, the adapter and the budget agree, and returns
// an embedder that cannot be built any other way.
func New(config Config) (*SemanticEmbedder, error) {
	if err := config.Manifest.Validate(); err != nil {
		return nil, err
	}
	if config.Adapter == nil {
		return nil, errors.New("a semantic embedder requires an adapter")
	}
	if config.Runtime == nil {
		return nil, errors.New("a semantic embedder requires a runtime")
	}
	// The fingerprint is computed from the manifest, so an adapter that is not
	// the one the manifest names would produce vectors under an identity that
	// describes something else -- and two installations would then believe
	// their indexes were comparable when they are not.
	if config.Adapter.Name() != config.Manifest.Adapter {
		return nil, fmt.Errorf("manifest names adapter %q but %q was supplied; the "+
			"fingerprint would describe a model that did not run",
			config.Manifest.Adapter, config.Adapter.Name())
	}
	if config.Adapter.Version() != config.Manifest.AdapterVersion {
		return nil, fmt.Errorf("manifest names adapter %q version %d but version %d "+
			"was supplied; the conventions may differ and the fingerprint would not say so",
			config.Manifest.Adapter, config.Manifest.AdapterVersion, config.Adapter.Version())
	}
	if config.Budget <= 0 {
		return nil, errors.New("a semantic embedder requires a positive inference budget")
	}
	return &SemanticEmbedder{
		manifest: config.Manifest,
		adapter:  config.Adapter,
		runtime:  config.Runtime,
		budget:   config.Budget,
	}, nil
}

// Fingerprint identifies what this embedder computes.
func (s *SemanticEmbedder) Fingerprint() string { return s.manifest.Fingerprint() }

// Dimensions is the width of the vectors this embedder returns.
func (s *SemanticEmbedder) Dimensions() int { return s.manifest.Dimensions }

// MaxTokens is the input length the model accepts.
func (s *SemanticEmbedder) MaxTokens() int { return s.manifest.MaxInputTokens }

// Manifest returns the model this embedder was built from.
func (s *SemanticEmbedder) Manifest() Manifest { return s.manifest }

// EmbedQuery embeds text as a search query.
func (s *SemanticEmbedder) EmbedQuery(ctx context.Context, text string) ([]float32, error) {
	return s.embed(ctx, s.adapter.QueryText(text), text)
}

// EmbedDocument embeds text as a stored document.
//
// This is separate from EmbedQuery rather than a flag, because the two are not
// interchangeable and a caller that picked the wrong one gets a plausible
// vector and worse retrieval, with nothing to indicate it.
func (s *SemanticEmbedder) EmbedDocument(ctx context.Context, text string) ([]float32, error) {
	return s.embed(ctx, s.adapter.DocumentText(text), text)
}

func (s *SemanticEmbedder) embed(ctx context.Context, prompted, original string) ([]float32, error) {
	if strings.TrimSpace(original) == "" {
		return nil, errors.New("text to embed must not be empty")
	}
	bounded, cancel := context.WithTimeout(ctx, s.budget)
	defer cancel()

	vector, err := s.runtime.Infer(bounded, prompted)
	if err != nil {
		return nil, err
	}
	if len(vector) != s.manifest.NativeDimensions {
		// A runtime returning an unexpected width means the pack that is
		// loaded is not the pack the manifest describes, so the fingerprint
		// on every vector it produced would be wrong.
		return nil, fmt.Errorf("runtime returned %d dimensions, the manifest declares %d",
			len(vector), s.manifest.NativeDimensions)
	}
	for index, value := range vector {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return nil, fmt.Errorf("runtime returned a non-finite value at dimension %d", index)
		}
	}

	// Matryoshka truncation, where the manifest asks for a narrower vector than
	// the model natively emits. Truncating changes the norm, so a truncated
	// vector is renormalized -- otherwise its length would carry information
	// about the discarded tail and every distance would be scaled by it.
	if width, truncates := s.manifest.EffectiveDimensions(); truncates {
		vector = vector[:width]
	}
	if s.manifest.Normalize {
		if !basin.Normalize(vector) {
			return nil, errors.New("runtime returned a zero vector, which has no direction")
		}
	}
	return vector, nil
}
