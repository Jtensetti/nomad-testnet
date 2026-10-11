package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A model pack is a directory holding one model and everything needed to know
// what it is and under what terms it may be redistributed.
//
// Nomad Core and the model packs are kept apart on purpose, and not only for
// tidiness. The three models worth shipping first are under three different
// licenses: multilingual-e5-small is MIT, Qwen3-Embedding-0.6B is Apache 2.0,
// and EmbeddingGemma is under Google's Gemma Terms, which are permissive about
// use and redistribution but oblige a redistributor to pass the terms on,
// include a NOTICE, and carry the use restrictions forward.
//
// Keeping the model outside the core means Nomad's own license never has to be
// reasoned about together with a model's. It also means swapping models later
// is an ordinary operation rather than a legal review.
const (
	ManifestFile = "manifest.json"
	NoticeFile   = "NOTICE"
	LicenseFile  = "LICENSE"

	// MaxManifestBytes bounds the manifest read. A manifest is a few hundred
	// bytes; anything near this is not one.
	MaxManifestBytes = 64 << 10
)

// Pack is a verified model pack on local disk.
type Pack struct {
	Directory string
	Manifest  Manifest
	// WeightsPath and TokenizerPath are the files whose digests were checked.
	WeightsPath   string
	TokenizerPath string
}

// Fingerprint identifies what this pack computes.
func (p Pack) Fingerprint() string { return p.Manifest.Fingerprint() }

// LoadPack reads and verifies a model pack.
//
// Verification is not optional and there is no mode that skips it. A pack whose
// weights do not match the digest in its manifest is refused, because the
// manifest is the only thing that says what those bytes are, and a fingerprint
// computed from a manifest that describes different bytes is a label on the
// wrong thing.
func LoadPack(directory string) (Pack, error) {
	manifest, err := readManifest(filepath.Join(directory, ManifestFile))
	if err != nil {
		return Pack{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Pack{}, fmt.Errorf("%s: %w", directory, err)
	}

	weights := filepath.Join(directory, "weights."+string(manifest.Runtime))
	if _, err := os.Stat(weights); err != nil {
		return Pack{}, fmt.Errorf("%s: no weights file at %s: %w", directory, weights, err)
	}
	tokenizer := filepath.Join(directory, "tokenizer.json")

	if err := verifyDigest(weights, manifest.WeightsSHA256, manifest.WeightsBytes); err != nil {
		return Pack{}, fmt.Errorf("%s weights: %w", directory, err)
	}
	if err := verifyDigest(tokenizer, manifest.TokenizerSHA256, 0); err != nil {
		return Pack{}, fmt.Errorf("%s tokenizer: %w", directory, err)
	}
	if err := verifyLicensing(directory, manifest); err != nil {
		return Pack{}, err
	}
	return Pack{
		Directory:     directory,
		Manifest:      manifest,
		WeightsPath:   weights,
		TokenizerPath: tokenizer,
	}, nil
}

func readManifest(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, err
	}
	if len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%s exceeds %d bytes", path, MaxManifestBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		// An unknown field is refused rather than ignored: a setting this
		// build does not understand is a setting that is not in the
		// fingerprint, and a fingerprint that omits something which changed
		// the vectors is worse than no fingerprint.
		return Manifest{}, fmt.Errorf("%s: %w", path, err)
	}
	if decoder.More() {
		return Manifest{}, fmt.Errorf("%s carries more than one JSON value", path)
	}
	return manifest, nil
}

// verifyDigest streams the file rather than reading it whole: weights are
// measured in gigabytes and this runs at install time on the reader's machine.
func verifyDigest(path, want string, expectedBytes int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("is not a regular file")
	}
	if expectedBytes > 0 && info.Size() != expectedBytes {
		return fmt.Errorf("is %d bytes, the manifest declares %d", info.Size(), expectedBytes)
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if got != want {
		return fmt.Errorf("digest is %s, the manifest declares %s", got, want)
	}
	return nil
}

// verifyLicensing refuses a pack that does not carry what its license requires.
//
// This is a redistribution obligation turned into a check. A pack under terms
// that oblige a NOTICE, shipped without one, is a licensing failure that no
// test would otherwise catch and that nobody notices until it matters.
func verifyLicensing(directory string, manifest Manifest) error {
	if err := nonEmptyFile(filepath.Join(directory, LicenseFile)); err != nil {
		return fmt.Errorf("%s: a model pack must carry its own LICENSE, which is not "+
			"Nomad's: %w", directory, err)
	}
	if !manifest.NoticeRequired {
		return nil
	}
	if err := nonEmptyFile(filepath.Join(directory, NoticeFile)); err != nil {
		return fmt.Errorf("%s: manifest declares license %q requires a NOTICE, and "+
			"redistributing without it is the obligation this check exists to "+
			"prevent breaking: %w", directory, manifest.License, err)
	}
	return nil
}

func nonEmptyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() == 0 || info.Size() > MaxNoticeBytes {
		return fmt.Errorf("%s is %d bytes", path, info.Size())
	}
	return nil
}

// Registry is the set of model packs installed on this machine.
type Registry struct {
	root  string
	packs map[string]Pack
}

// OpenRegistry loads every pack under root, skipping directories that do not
// verify and reporting how many were skipped.
//
// One unverifiable pack must not hide the others, for the same reason one
// hostile object does not stop a cache from loading. The count is returned
// rather than logged, because a registry that silently offers fewer models
// than are installed looks exactly like one with fewer models installed.
func OpenRegistry(root string) (*Registry, int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0, fmt.Errorf("reading the model registry: %w", err)
	}
	registry := &Registry{root: root, packs: map[string]Pack{}}
	rejected := 0
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		pack, err := LoadPack(filepath.Join(root, entry.Name()))
		if err != nil {
			rejected++
			continue
		}
		registry.packs[pack.Fingerprint()] = pack
	}
	return registry, rejected, nil
}

// Installed lists the verified packs, ordered by model id then fingerprint.
func (r *Registry) Installed() []Pack {
	packs := make([]Pack, 0, len(r.packs))
	for _, pack := range r.packs {
		packs = append(packs, pack)
	}
	sortPacks(packs)
	return packs
}

// ByFingerprint returns the pack that computes a given fingerprint.
//
// Lookup is by fingerprint rather than by id because an id does not identify
// what an index was built with. Two packs can share an id and produce
// incomparable vectors; only the fingerprint distinguishes them.
func (r *Registry) ByFingerprint(fingerprint string) (Pack, bool) {
	pack, ok := r.packs[fingerprint]
	return pack, ok
}

func sortPacks(packs []Pack) {
	sort.Slice(packs, func(a, b int) bool {
		if packs[a].Manifest.ID != packs[b].Manifest.ID {
			return packs[a].Manifest.ID < packs[b].Manifest.ID
		}
		return packs[a].Fingerprint() < packs[b].Fingerprint()
	})
}
