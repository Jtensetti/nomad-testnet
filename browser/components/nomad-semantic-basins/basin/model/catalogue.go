package model

// The catalogue is what a client offers to install. It is deliberately not a
// set of manifests.
//
// A manifest carries the digests of the exact weights and tokenizer a pack
// ships, and those digests can only be known by whoever built that pack from
// those files. Writing plausible-looking digests here would produce a registry
// that verifies packs against numbers nobody measured, which is worse than
// having no verification: it would look verified.
//
// So an entry describes what a model *is* -- family, width, license, where it
// comes from, what it costs to run -- and a pack builder produces the manifest
// with the digests filled in from the files that actually shipped.

// Availability says whether a model is expected in a base install or offered
// as a separate download.
type Availability string

const (
	// Bundled ships with the client, so semantic search works on first start.
	Bundled Availability = "bundled"
	// Downloadable is offered in the interface and fetched on request, which
	// keeps the base install small.
	Downloadable Availability = "downloadable"
)

// CatalogueEntry is one offerable model.
type CatalogueEntry struct {
	ID      string
	Title   string
	Summary string

	Adapter        string
	AdapterVersion int
	Runtime        RuntimeKind

	NativeDimensions int
	SupportedDims    []int
	// RecommendedDimensions is the width to configure by default. For a model
	// trained for Matryoshka truncation this may be well below native.
	RecommendedDimensions int
	MaxInputTokens        int
	Normalize             bool

	License string
	// NoticeRequired marks a license that obliges a redistributor to carry a
	// NOTICE. LoadPack refuses such a pack without one.
	NoticeRequired bool
	Source         string

	Availability Availability
}

// Catalogue is the set of models this build knows how to offer.
//
// EmbeddingGemma is the recommended default and the others are first-class
// alternatives, which is a recommendation and not a dependency: the core has
// no knowledge of any of them beyond this table and the adapters they name.
func Catalogue() []CatalogueEntry {
	return []CatalogueEntry{
		{
			ID:      "embeddinggemma-300m",
			Title:   "EmbeddingGemma 300M",
			Summary: "Recommended. Built for on-device semantic search, and small for its quality.",

			Adapter:        "gemma",
			AdapterVersion: GemmaAdapter{}.Version(),
			Runtime:        RuntimeGGUF,

			NativeDimensions:      768,
			SupportedDims:         []int{768, 512, 256, 128},
			RecommendedDimensions: 256,
			MaxInputTokens:        2048,
			Normalize:             true,

			// Not MIT and not Apache 2.0. Google's Gemma Terms permit use and
			// redistribution but oblige a redistributor to pass the terms on,
			// include a NOTICE and carry the use restrictions forward -- which
			// is exactly why model packs are separate artifacts from the core,
			// and why NoticeRequired is enforced rather than documented.
			License:        "Gemma Terms of Use",
			NoticeRequired: true,
			Source:         "https://huggingface.co/google/embeddinggemma-300m",

			Availability: Bundled,
		},
		{
			ID:      "multilingual-e5-small",
			Title:   "multilingual-e5-small",
			Summary: "Lightweight. The smallest of the three, and the simplest to redistribute.",

			Adapter:        "e5",
			AdapterVersion: E5Adapter{}.Version(),
			Runtime:        RuntimeONNX,

			NativeDimensions:      384,
			SupportedDims:         []int{384},
			RecommendedDimensions: 384,
			MaxInputTokens:        512,
			Normalize:             true,

			License:        "MIT",
			NoticeRequired: false,
			Source:         "https://huggingface.co/intfloat/multilingual-e5-small",

			Availability: Downloadable,
		},
		{
			ID:      "qwen3-embedding-0.6b",
			Title:   "Qwen3 Embedding 0.6B",
			Summary: "Higher quality, for readers who would rather spend CPU and memory on ranking.",

			Adapter:        "qwen",
			AdapterVersion: QwenAdapter{}.Version(),
			Runtime:        RuntimeGGUF,

			NativeDimensions:      1024,
			SupportedDims:         []int{1024, 768, 512, 256},
			RecommendedDimensions: 1024,
			MaxInputTokens:        8192,
			Normalize:             true,

			License:        "Apache-2.0",
			NoticeRequired: true,
			Source:         "https://huggingface.co/Qwen/Qwen3-Embedding-0.6B",

			Availability: Downloadable,
		},
	}
}
