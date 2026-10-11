// Command nomad-model inspects and verifies a model pack.
//
// It exists because a pack is the one artifact a reader installs that this
// project did not build: weights and a tokenizer from elsewhere, under a
// license that is not Nomad's. Before any of that is used, someone should be
// able to ask what it actually is.
//
// It does not run a model. Verifying a pack means hashing its files and
// reading its manifest, and neither needs an inference runtime, so this tool
// links none -- which is what lets it share the browser's guarantee of having
// no socket and no subprocess in its dependency graph.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Jtensetti/nomad-semantic-basins/basin/model"

	"github.com/Jtensetti/nomad-browser/search"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-model:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("nomad-model", flag.ContinueOnError)
	flags.SetOutput(output)
	catalogue := flags.Bool("catalogue", false, "list the models this build can offer")
	root := flags.String("registry", "", "directory of installed model packs")
	pack := flags.String("pack", "", "a single model pack to verify")
	indexRoot := flags.String("index-root", ".", "where indexes are stored, for reporting paths")
	if err := flags.Parse(args); err != nil {
		return err
	}

	switch {
	case *catalogue:
		return listCatalogue(output)
	case *pack != "":
		return describePack(output, *pack, *indexRoot)
	case *root != "":
		return describeRegistry(output, *root, *indexRoot)
	}
	return fmt.Errorf("nothing to do: pass -catalogue, -pack or -registry")
}

func listCatalogue(output io.Writer) error {
	fmt.Fprintln(output, "Models this build can offer. A catalogue entry is not a pack:")
	fmt.Fprintln(output, "its digests are filled in by whoever built the pack from the files")
	fmt.Fprintln(output, "that actually shipped.")
	for _, entry := range model.Catalogue() {
		fmt.Fprintf(output, "\n%s\n  %s\n", entry.Title, entry.Summary)
		fmt.Fprintf(output, "  id           %s\n", entry.ID)
		fmt.Fprintf(output, "  adapter      %s v%d over %s\n",
			entry.Adapter, entry.AdapterVersion, entry.Runtime)
		fmt.Fprintf(output, "  dimensions   %d recommended of %d native %v\n",
			entry.RecommendedDimensions, entry.NativeDimensions, entry.SupportedDims)
		fmt.Fprintf(output, "  tokens       %d\n", entry.MaxInputTokens)
		fmt.Fprintf(output, "  license      %s%s\n", entry.License, noticeNote(entry.NoticeRequired))
		fmt.Fprintf(output, "  source       %s\n", entry.Source)
		fmt.Fprintf(output, "  install      %s\n", entry.Availability)
	}
	return nil
}

func noticeNote(required bool) string {
	if required {
		return " (redistribution requires carrying a NOTICE)"
	}
	return ""
}

func describePack(output io.Writer, directory, indexRoot string) error {
	loaded, err := model.LoadPack(directory)
	if err != nil {
		// A pack that does not verify is not described as though it might be
		// fine. The digest is the only thing that says what the weights are.
		return err
	}
	return report(output, loaded, indexRoot)
}

func describeRegistry(output io.Writer, root, indexRoot string) error {
	registry, rejected, err := model.OpenRegistry(root)
	if err != nil {
		return err
	}
	installed := registry.Installed()
	fmt.Fprintf(output, "%d verified packs in %s\n", len(installed), root)
	if rejected > 0 {
		// Reported, never swallowed: a registry offering fewer models than are
		// installed looks the same as one with fewer models installed.
		fmt.Fprintf(output, "%d directories did not verify and are not offered\n", rejected)
	}
	for _, loaded := range installed {
		fmt.Fprintln(output)
		if err := report(output, loaded, indexRoot); err != nil {
			return err
		}
	}
	return nil
}

func report(output io.Writer, pack model.Pack, indexRoot string) error {
	manifest := pack.Manifest
	fingerprint := pack.Fingerprint()

	fmt.Fprintf(output, "%s %s\n", manifest.ID, manifest.Version)
	fmt.Fprintf(output, "  fingerprint  %s\n", fingerprint)
	fmt.Fprintf(output, "  adapter      %s v%d over %s, %s\n",
		manifest.Adapter, manifest.AdapterVersion, manifest.Runtime, manifest.Quantization)

	width, truncates := manifest.EffectiveDimensions()
	if truncates {
		fmt.Fprintf(output, "  dimensions   %d, truncated from %d and renormalized\n",
			width, manifest.NativeDimensions)
	} else {
		fmt.Fprintf(output, "  dimensions   %d\n", width)
	}
	fmt.Fprintf(output, "  license      %s%s\n", manifest.License, noticeNote(manifest.NoticeRequired))

	// The fingerprint is what an index is stored under, so print the path a
	// reader would look in rather than leaving them to derive it.
	directory, err := search.NewManager(indexRoot).Directory(fingerprint)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "  index        %s\n", directory)

	if settings := manifest.InferenceSettings; len(settings) > 0 {
		keys := make([]string, 0, len(settings))
		for key := range settings {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		fmt.Fprintf(output, "  settings     %s\n", strings.Join(keys, ", "))
	}
	fmt.Fprintf(output, "  verified     %s and %s match their digests\n",
		filepath.Base(pack.WeightsPath), filepath.Base(pack.TokenizerPath))
	return nil
}
