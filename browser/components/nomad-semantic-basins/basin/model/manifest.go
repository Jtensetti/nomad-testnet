// Package model makes Nomad's semantic search independent of any particular
// embedding model.
//
// Nomad uses embeddings; it is not built around an embedding model. Nothing in
// the core knows what EmbeddingGemma, E5 or Qwen are. What it knows is a
// manifest describing a model, an adapter carrying that model family's
// conventions, and a runtime that turns text into a vector. A model family
// that does not exist yet is added by writing an adapter, and nothing else
// moves.
//
// The package is deliberately socket-free and weightless. It does not download,
// execute or contain a model: a Runtime is supplied by a model pack, which is a
// separate artifact with its own license. See registry.go for why that
// separation is enforced by code rather than described in a document.
package model

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// SchemaVersion is the manifest format's version. It is part of the
// fingerprint, so a format change cannot silently make two indexes look
// comparable.
const SchemaVersion = 1

// Bounds on manifest values. They are checked when a manifest is parsed rather
// than when a model is first run, so a malformed pack is refused before any of
// its bytes reach a runtime.
const (
	MaxIDRunes           = 128
	MaxLicenseRunes      = 128
	MaxNoticeBytes       = 1 << 20
	MaxSourceRunes       = 2048
	MaxSupportedDims     = 32
	MaxInferenceSettings = 32
	MinDimensions        = 8
	MaxDimensions        = 1 << 16
	MinTokens            = 16
	MaxTokens            = 1 << 20
	MaxWeightBytes       = 64 << 30
)

// RuntimeKind names how a model pack executes. The core does not implement any
// of these; it records which one a pack claims so that a pack cannot be loaded
// by a runtime that was built for a different format.
type RuntimeKind string

const (
	RuntimeGGUF     RuntimeKind = "gguf"
	RuntimeONNX     RuntimeKind = "onnx"
	RuntimeLoopback RuntimeKind = "loopback"
)

func (k RuntimeKind) known() bool {
	switch k {
	case RuntimeGGUF, RuntimeONNX, RuntimeLoopback:
		return true
	}
	return false
}

// Manifest describes one model completely enough that two installations can
// tell whether their embeddings are comparable.
//
// Every field that can change what a vector is must be present here, because
// the fingerprint is computed from this and nothing else. A field that affects
// output and is not in the manifest is a field that lets two incompatible
// indexes claim to be the same one.
type Manifest struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	// Version is the model release, not the manifest revision. Two manifests
	// for the same weights differ in Revision; two model releases differ here.
	Version  string `json:"version"`
	Revision int    `json:"revision"`

	Runtime      RuntimeKind `json:"runtime"`
	Quantization string      `json:"quantization"`

	// Adapter names the family conventions this model needs. It is separate
	// from ID because several models share a family, and because the adapter's
	// own version participates in the fingerprint: a fix to how queries are
	// prefixed changes every vector the adapter produces.
	Adapter        string `json:"adapter"`
	AdapterVersion int    `json:"adapterVersion"`

	// Dimensions is the width this model is configured to emit. It may be
	// below NativeDimensions where the model supports Matryoshka truncation,
	// in which case the adapter truncates and renormalizes.
	Dimensions       int   `json:"dimensions"`
	NativeDimensions int   `json:"nativeDimensions"`
	SupportedDims    []int `json:"supportedDimensions"`
	Normalize        bool  `json:"normalize"`
	MaxInputTokens   int   `json:"maxInputTokens"`

	// InferenceSettings carries anything else that changes output: a pooling
	// strategy, a temperature, a thread count that affects reduction order.
	// It is a map so a pack can record settings this package has never heard
	// of, and it is in the fingerprint so those settings cannot drift unnoticed.
	InferenceSettings map[string]string `json:"inferenceSettings,omitempty"`

	WeightsSHA256   string `json:"weightsSha256"`
	TokenizerSHA256 string `json:"tokenizerSha256"`
	WeightsBytes    int64  `json:"weightsBytes"`

	// License is the model's own license, which is not Nomad's. See registry.go.
	License        string `json:"license"`
	NoticeRequired bool   `json:"noticeRequired"`
	Source         string `json:"source"`

	// Requirements is advisory: what the pack says it needs to run usefully.
	// It is not part of the fingerprint, because a model does not produce
	// different vectors on a machine with more memory.
	Requirements Requirements `json:"requirements"`
}

// Requirements is what a pack reports it needs. It is advisory and is
// deliberately outside the fingerprint.
type Requirements struct {
	MinimumRAMBytes int64  `json:"minimumRamBytes"`
	Threads         int    `json:"threads"`
	Accelerator     string `json:"accelerator,omitempty"`
}

// Validate refuses a manifest that could not describe a usable model, or that
// leaves something undetermined which the fingerprint would then have to
// pretend was fixed.
func (m Manifest) Validate() error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("manifest schema is %d, this build understands %d", m.Schema, SchemaVersion)
	}
	if err := boundedField("id", m.ID, MaxIDRunes); err != nil {
		return err
	}
	if err := boundedField("version", m.Version, MaxIDRunes); err != nil {
		return err
	}
	if m.Revision < 0 {
		return errors.New("manifest revision must not be negative")
	}
	if !m.Runtime.known() {
		return fmt.Errorf("manifest names an unknown runtime %q", m.Runtime)
	}
	if err := boundedField("adapter", m.Adapter, MaxIDRunes); err != nil {
		return err
	}
	if m.AdapterVersion < 1 {
		return errors.New("manifest must name a positive adapter version")
	}
	if m.NativeDimensions < MinDimensions || m.NativeDimensions > MaxDimensions {
		return fmt.Errorf("native dimensions %d are outside [%d, %d]",
			m.NativeDimensions, MinDimensions, MaxDimensions)
	}
	if m.Dimensions < MinDimensions || m.Dimensions > m.NativeDimensions {
		return fmt.Errorf("dimensions %d are outside [%d, %d]",
			m.Dimensions, MinDimensions, m.NativeDimensions)
	}
	if len(m.SupportedDims) == 0 {
		return errors.New("manifest must list the dimensions this model supports")
	}
	if len(m.SupportedDims) > MaxSupportedDims {
		return fmt.Errorf("manifest lists %d supported dimensions, at most %d",
			len(m.SupportedDims), MaxSupportedDims)
	}
	if !slices.Contains(m.SupportedDims, m.Dimensions) {
		// Truncating to a width the model was not trained to truncate to
		// produces vectors that still look like vectors and rank badly, which
		// is the kind of failure nobody reports as a bug.
		return fmt.Errorf("configured dimensions %d are not among the supported %v",
			m.Dimensions, m.SupportedDims)
	}
	if !slices.Contains(m.SupportedDims, m.NativeDimensions) {
		return fmt.Errorf("native dimensions %d are not among the supported %v",
			m.NativeDimensions, m.SupportedDims)
	}
	if m.MaxInputTokens < MinTokens || m.MaxInputTokens > MaxTokens {
		return fmt.Errorf("maximum input tokens %d are outside [%d, %d]",
			m.MaxInputTokens, MinTokens, MaxTokens)
	}
	if len(m.InferenceSettings) > MaxInferenceSettings {
		return fmt.Errorf("manifest carries %d inference settings, at most %d",
			len(m.InferenceSettings), MaxInferenceSettings)
	}
	for key, value := range m.InferenceSettings {
		if err := boundedField("inference setting name", key, MaxIDRunes); err != nil {
			return err
		}
		if err := boundedField("inference setting "+key, value, MaxSourceRunes); err != nil {
			return err
		}
	}
	if err := validDigest("weights", m.WeightsSHA256); err != nil {
		return err
	}
	if err := validDigest("tokenizer", m.TokenizerSHA256); err != nil {
		return err
	}
	if m.WeightsBytes <= 0 || m.WeightsBytes > MaxWeightBytes {
		return fmt.Errorf("weights size %d is outside (0, %d]", m.WeightsBytes, MaxWeightBytes)
	}
	if err := boundedField("license", m.License, MaxLicenseRunes); err != nil {
		return err
	}
	if err := boundedField("source", m.Source, MaxSourceRunes); err != nil {
		return err
	}
	if m.Requirements.MinimumRAMBytes < 0 || m.Requirements.Threads < 0 {
		return errors.New("manifest requirements must not be negative")
	}
	return nil
}

// EffectiveDimensions reports whether this manifest asks for Matryoshka
// truncation, and to what width.
func (m Manifest) EffectiveDimensions() (width int, truncates bool) {
	return m.Dimensions, m.Dimensions < m.NativeDimensions
}

func boundedField(name, value string, limit int) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("manifest %s is empty", name)
	}
	if len([]rune(value)) > limit {
		return fmt.Errorf("manifest %s exceeds %d characters", name, limit)
	}
	if trimmed != value {
		// Surrounding whitespace would make two manifests that name the same
		// thing produce two fingerprints.
		return fmt.Errorf("manifest %s has surrounding whitespace", name)
	}
	return nil
}

func validDigest(name, value string) error {
	if len(value) != 64 {
		return fmt.Errorf("%s digest is %d characters, want 64 hex", name, len(value))
	}
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		default:
			// Lowercase only: accepting both cases would let one digest have
			// two spellings and so one model have two fingerprints.
			return fmt.Errorf("%s digest is not lowercase hex", name)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
