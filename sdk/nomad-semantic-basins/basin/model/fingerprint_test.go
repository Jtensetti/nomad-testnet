package model

import (
	"reflect"
	"testing"
)

// validManifest is a manifest that passes Validate, so a negative case can
// break exactly one thing.
func validManifest() Manifest {
	return Manifest{
		Schema:            SchemaVersion,
		ID:                "embeddinggemma-300m",
		Version:           "1.0.0",
		Revision:          1,
		Runtime:           RuntimeGGUF,
		Quantization:      "q8_0",
		Adapter:           "gemma",
		AdapterVersion:    1,
		Dimensions:        256,
		NativeDimensions:  768,
		SupportedDims:     []int{768, 512, 256, 128},
		Normalize:         true,
		MaxInputTokens:    2048,
		InferenceSettings: map[string]string{"pooling": "mean"},
		WeightsSHA256:     "1111111111111111111111111111111111111111111111111111111111111111",
		TokenizerSHA256:   "2222222222222222222222222222222222222222222222222222222222222222",
		WeightsBytes:      200 << 20,
		License:           "Gemma Terms of Use",
		NoticeRequired:    true,
		Source:            "https://example.invalid/embeddinggemma-300m",
		Requirements:      Requirements{MinimumRAMBytes: 200 << 20, Threads: 2},
	}
}

// fingerprintClassification records, for every field of Manifest, whether it
// may move the fingerprint.
//
// It exists so that adding a field to Manifest fails this test until somebody
// decides which side it is on. A new setting that changes what a vector is,
// left out of the fingerprint, would let two incomparable indexes carry the
// same identity -- and no test that only checks the fields known today would
// ever notice.
var fingerprintClassification = map[string]bool{
	// Changes what a vector is.
	"Schema":            true,
	"Runtime":           true,
	"Quantization":      true,
	"Adapter":           true,
	"AdapterVersion":    true,
	"Dimensions":        true,
	"NativeDimensions":  true,
	"Normalize":         true,
	"MaxInputTokens":    true,
	"InferenceSettings": true,
	"WeightsSHA256":     true,
	"TokenizerSHA256":   true,

	// Does not. A renamed model, a corrected download URL or a machine with
	// more memory does not produce different embeddings, and forcing a reindex
	// for one of those would teach people to avoid correcting them.
	// The list of widths a model supports constrains which configurations are
	// valid; it does not change the vector produced at a fixed width. Two
	// manifests differing only here, both configured to 256, emit the same
	// embeddings and belong in the same index.
	"SupportedDims": false,

	"ID":             false,
	"Version":        false,
	"Revision":       false,
	"WeightsBytes":   false,
	"License":        false,
	"NoticeRequired": false,
	"Source":         false,
	"Requirements":   false,
}

// mutate returns a different value of the same type, so a field can be changed
// without knowing what it means.
func mutate(value reflect.Value) (reflect.Value, bool) {
	switch value.Kind() {
	case reflect.String:
		return reflect.ValueOf(value.String() + "x").Convert(value.Type()), true
	case reflect.Int, reflect.Int64:
		return reflect.ValueOf(value.Int() + 1).Convert(value.Type()), true
	case reflect.Bool:
		return reflect.ValueOf(!value.Bool()).Convert(value.Type()), true
	case reflect.Slice:
		grown := reflect.Append(value, reflect.Zero(value.Type().Elem()))
		return grown, true
	case reflect.Map:
		grown := reflect.MakeMap(value.Type())
		for _, key := range value.MapKeys() {
			grown.SetMapIndex(key, value.MapIndex(key))
		}
		grown.SetMapIndex(reflect.ValueOf("added").Convert(value.Type().Key()),
			reflect.ValueOf("value").Convert(value.Type().Elem()))
		return grown, true
	case reflect.Struct:
		// Requirements: change its first settable field.
		copied := reflect.New(value.Type()).Elem()
		copied.Set(value)
		for index := 0; index < copied.NumField(); index++ {
			field := copied.Field(index)
			if !field.CanSet() {
				continue
			}
			if changed, ok := mutate(field); ok {
				field.Set(changed)
				return copied, true
			}
		}
	}
	return reflect.Value{}, false
}

// Every field of Manifest is either in the fingerprint or deliberately out of
// it, and this checks both directions against the real digest.
func TestEveryManifestFieldIsClassifiedAgainstTheFingerprint(t *testing.T) {
	base := validManifest()
	baseline := base.Fingerprint()

	structType := reflect.TypeOf(base)
	for index := 0; index < structType.NumField(); index++ {
		name := structType.Field(index).Name
		t.Run(name, func(t *testing.T) {
			shouldMove, classified := fingerprintClassification[name]
			if !classified {
				t.Fatalf("Manifest.%s is new and unclassified. Decide whether it can "+
					"change what a vector is: if it can it must reach "+
					"Manifest.canonical, and either way it must be listed in "+
					"fingerprintClassification", name)
			}

			changed := reflect.New(structType).Elem()
			changed.Set(reflect.ValueOf(base))
			mutated, ok := mutate(changed.Field(index))
			if !ok {
				t.Fatalf("no mutation is defined for %s of kind %s; extend mutate "+
					"rather than skipping the field", name, changed.Field(index).Kind())
			}
			changed.Field(index).Set(mutated)

			moved := changed.Interface().(Manifest).Fingerprint() != baseline
			if moved != shouldMove {
				if shouldMove {
					t.Fatalf("changing %s left the fingerprint unchanged, so two models "+
						"that differ in it would share an index", name)
				}
				t.Fatalf("changing %s moved the fingerprint, which forces a reindex for "+
					"something that does not change a vector", name)
			}
		})
	}
}

// The classification table itself must not drift out of the struct.
func TestTheClassificationTableNamesOnlyRealFields(t *testing.T) {
	structType := reflect.TypeOf(Manifest{})
	present := map[string]bool{}
	for index := 0; index < structType.NumField(); index++ {
		present[structType.Field(index).Name] = true
	}
	for name := range fingerprintClassification {
		if !present[name] {
			t.Errorf("fingerprintClassification names %s, which Manifest no longer has", name)
		}
	}
}

// Two models under one name is the case the fingerprint exists for.
func TestOneNameCanCoverTwoIncomparableModels(t *testing.T) {
	first := validManifest()
	second := validManifest()
	second.WeightsSHA256 = "3333333333333333333333333333333333333333333333333333333333333333"

	if first.ID != second.ID {
		t.Fatal("the fixtures no longer share an id, so this proves nothing")
	}
	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("two different sets of weights under one id share a fingerprint, so " +
			"their embeddings would be compared with each other")
	}
}

// A fingerprint is a function of the manifest and of nothing else -- not of
// map iteration order, and not of when it is computed.
func TestTheFingerprintIsStableAcrossRunsAndMapOrder(t *testing.T) {
	want := validManifest().Fingerprint()
	for attempt := 0; attempt < 32; attempt++ {
		manifest := validManifest()
		// Rebuild the settings map so its internal order differs between runs.
		manifest.InferenceSettings = map[string]string{}
		for _, key := range []string{"pooling"} {
			manifest.InferenceSettings[key] = validManifest().InferenceSettings[key]
		}
		manifest.InferenceSettings["z"] = "1"
		manifest.InferenceSettings["a"] = "2"

		reference := validManifest()
		reference.InferenceSettings = map[string]string{"a": "2", "pooling": "mean", "z": "1"}

		if manifest.Fingerprint() != reference.Fingerprint() {
			t.Fatalf("attempt %d: two manifests with the same settings fingerprinted differently", attempt)
		}
		if validManifest().Fingerprint() != want {
			t.Fatalf("attempt %d: the same manifest fingerprinted differently", attempt)
		}
	}
}

// The digest is domain-separated, so it cannot collide with another SHA-256
// over the same material.
func TestTheFingerprintIsDomainSeparated(t *testing.T) {
	manifest := validManifest()
	canonical := manifest.canonical()
	if len(canonical) < len(fingerprintDomain) {
		t.Fatal("the canonical encoding is shorter than its domain tag")
	}
	if string(canonical[:len(fingerprintDomain)]) != string(fingerprintDomain) {
		t.Fatal("the canonical encoding does not begin with the domain tag")
	}
}

// Length prefixes, not concatenation: two different splits of the same
// characters must not produce one byte string.
//
// The fields chosen have to be adjacent in the canonical encoding, or the
// test cannot fail. The first version of this used Quantization and Adapter,
// which are four fields apart, so the two digests between them separated the
// strings no matter how the encoding worked -- it passed against a build with
// the length prefixes removed. Runtime and Quantization are neighbours, and
// the mutation kills it.
func TestAdjacentFieldsCannotBeConfused(t *testing.T) {
	first := validManifest()
	first.Runtime = RuntimeKind("gguf")
	first.Quantization = "q8_0"

	second := validManifest()
	second.Runtime = RuntimeKind("ggufq8_0")
	second.Quantization = ""

	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("moving characters across a field boundary left the fingerprint " +
			"unchanged, so the canonical encoding concatenates rather than " +
			"length-prefixes, and two different models can share an identity")
	}
}
