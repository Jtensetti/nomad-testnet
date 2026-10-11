// Command nomad-browser is the Linux Nomad client.
//
// It is a reader for verified local objects, not a web browser: there is no
// address field, no engine, no resolver and no socket. Its dependency graph is
// asserted to contain no networking package at all (see architecture_test.go
// at the repository root), and the launcher in linux/ runs it in a network
// namespace with no interfaces, so the claim is enforced by the kernel rather
// than by this program's good behaviour.
//
// Commands are read from standard input, one per line, which is the same path
// whether a person is typing them or a test is piping them.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Jtensetti/nomad-semantic-basins/basin"

	"github.com/Jtensetti/nomad-browser/objectstore"
	"github.com/Jtensetti/nomad-browser/search"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-browser:", err)
		os.Exit(1)
	}
}

type options struct {
	directory  string
	trust      string
	budget     time.Duration
	dimensions int
	reload     time.Duration
}

// DefaultReloadInterval is how often the client rescans its object directory.
//
// It is a constant of this program, not a function of anything the reader
// does. The materializer writes objects on its own schedule and this client
// has no way to be told about one, so a rescan is the only way a new object
// becomes visible -- and rescanning on a command, or faster when a search
// returned nothing, would make the reader's activity the thing that drives it.
const DefaultReloadInterval = 30 * time.Second

func run(args []string, input io.Reader, output io.Writer) error {
	var opts options
	flags := flag.NewFlagSet("nomad-browser", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.directory, "objects", defaultObjectDirectory(),
		"directory of verified .nomadobject files")
	flags.StringVar(&opts.trust, "trust", "",
		"comma-separated base64 Ed25519 publisher keys this client will render")
	flags.DurationVar(&opts.budget, "budget", 2*time.Second,
		"time limit for one embedding call")
	flags.IntVar(&opts.dimensions, "dimensions", 256, "embedding dimensions")
	flags.DurationVar(&opts.reload, "reload", DefaultReloadInterval,
		"how often to rescan the object directory; 0 scans once at startup and never again")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(opts.trust) == "" {
		// A client with nothing anchored would either render everything or
		// nothing. Both are worse than saying which it needs.
		return fmt.Errorf("-trust is required: a client that renders objects " +
			"without an anchored publisher key is trusting whoever wrote the directory")
	}
	trusted, err := objectstore.ParseTrustSet(strings.Split(opts.trust, ",")...)
	if err != nil {
		return err
	}

	scan, err := objectstore.Load(opts.directory, trusted)
	if err != nil {
		return err
	}

	// One index per fingerprint, so that attaching a semantic model later adds
	// an index rather than overwriting this one. The baseline gets a
	// fingerprint like any model would: an index without one is an index whose
	// vectors could be compared with something incomparable.
	indexes := search.NewManager(opts.directory)
	index, err := indexes.Open(search.Config{
		Embedder:    basin.LexicalHashEmbedder{Dims: opts.dimensions},
		Quantizer:   basin.Quantizer{Seed: localRankingSeed()},
		Provenance:  search.ProvenanceLexical,
		Fingerprint: search.LexicalFingerprint(opts.dimensions),
		Budget:      opts.budget,
	})
	if err != nil {
		return err
	}
	ctx := context.Background()
	indexed, unindexed := index.AddAll(ctx, scan.Objects)

	session := &session{
		objects:   scan.Objects,
		index:     index,
		output:    output,
		directory: opts.directory,
		trusted:   trusted,
	}
	session.banner(scan.Rejected, indexed, unindexed)

	if opts.reload > 0 {
		ctx, stop := context.WithCancel(ctx)
		defer stop()
		go session.rescanUntil(ctx, opts.reload)
	}
	return session.loop(ctx, input)
}

// localRankingSeed fixes the basin quantizer for this client's own ranking.
//
// It is deliberately a constant of this program and not a protocol value. The
// basins computed here order one reader's local results and are never sent,
// compared across clients, or used to select anything on the network, so
// nothing outside this process depends on the seed being any particular value
// -- only on it being the same from one run to the next.
func localRankingSeed() [32]byte {
	return sha256.Sum256([]byte("nomad-browser-local-ranking-v1"))
}

func defaultObjectDirectory() string {
	if directory := os.Getenv("NOMAD_OBJECT_DIR"); directory != "" {
		return directory
	}
	// XDG_DATA_HOME, then its documented default. Nothing here creates the
	// directory: a missing cache is reported, not invented.
	if data := os.Getenv("XDG_DATA_HOME"); data != "" {
		return data + "/nomad/objects"
	}
	return os.Getenv("HOME") + "/.local/share/nomad/objects"
}

type session struct {
	output    io.Writer
	directory string
	trusted   objectstore.TrustSet
	index     *search.Index

	// observed, when set, is called with the instant of every rescan. Only the
	// query-independence test uses it: a rescan has no other externally
	// visible effect, so there would otherwise be nothing to measure.
	observed func(time.Time)

	mutex   sync.RWMutex
	objects []objectstore.Object
	last    rescan
}

// rescan is what the most recent directory scan found. It is reported by the
// status command rather than printed when it happens: a line arriving in the
// middle of someone typing is noise, and a rescan that failed silently is the
// thing this record exists to prevent.
type rescan struct {
	at       time.Time
	ran      bool
	err      error
	verified int
	rejected int
	added    int
	removed  int
	failed   int
}

// rescanUntil rescans on a fixed interval until the context ends.
//
// The ticker is the only thing that drives it. No command, no query, no empty
// result set and no failure changes when the next one happens, which is the
// whole property: cache discovery is a public periodic process, and what it
// finds is private to this reader.
func (s *session) rescanUntil(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.rescan(ctx)
		}
	}
}

func (s *session) rescan(ctx context.Context) {
	now := time.Now()
	if s.observed != nil {
		s.observed(now)
	}
	scan, err := objectstore.Load(s.directory, s.trusted)
	if err != nil {
		s.mutex.Lock()
		s.last = rescan{at: now, ran: true, err: err}
		s.mutex.Unlock()
		return
	}
	added, failed, removed := s.index.Sync(ctx, scan.Objects)
	s.mutex.Lock()
	s.objects = scan.Objects
	s.last = rescan{at: now, ran: true, verified: len(scan.Objects), rejected: scan.Rejected,
		added: added, removed: removed, failed: failed}
	s.mutex.Unlock()
}

func (s *session) snapshot() []objectstore.Object {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.objects
}

func (s *session) printf(format string, args ...any) {
	fmt.Fprintf(s.output, format, args...)
}

func (s *session) banner(rejected, indexed, unindexed int) {
	s.printf("nomad-browser: %d verified objects, %d searchable\n", len(s.objects), indexed)
	if rejected > 0 {
		// Reported, never swallowed: a client rendering fewer objects than the
		// directory holds looks the same as one that was given fewer.
		s.printf("%d files in the object directory did not verify\n", rejected)
	}
	if unindexed > 0 {
		s.printf("%d verified objects could not be indexed and are not searchable\n", unindexed)
	}
	s.printf("ranking: %s. There is no semantic model in this build; a lexical\n"+
		"ranking is a word match, not an understanding of meaning.\n", s.index.Provenance())
	s.printf("commands: list, search <text>, read <id>, help, quit\n")
}

func (s *session) loop(ctx context.Context, input io.Reader) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 4096), maxCommandBytes)
	for scanner.Scan() {
		command, argument, _ := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		argument = strings.TrimSpace(argument)
		switch command {
		case "":
			continue
		case "quit", "exit":
			return nil
		case "help":
			s.printf("list                 every verified object\n" +
				"status               what the last directory rescan found\n" +
				"search <text>        rank objects against text\n" +
				"read <id>            render one object by id prefix\n" +
				"quit                 leave\n")
		case "list":
			s.list()
		case "status":
			s.status()
		case "search":
			if err := s.search(ctx, argument); err != nil {
				s.printf("search failed: %v\n", err)
			}
		case "read":
			s.read(argument)
		default:
			s.printf("unknown command %q; try help\n", command)
		}
	}
	return scanner.Err()
}

// maxCommandBytes bounds one input line. A command is a query or an object id,
// and neither is large.
const maxCommandBytes = 8 << 10

// shortID is how many hex characters of the commitment identify an object in
// the interface. The full id stays available through read, which accepts any
// unambiguous prefix.
const shortID = 12

func (s *session) list() {
	objects := s.snapshot()
	if len(objects) == 0 {
		s.printf("no verified objects\n")
		return
	}
	for _, object := range objects {
		s.printf("%s  %s\n", object.ID[:shortID], object.Document.Title)
	}
}

func (s *session) search(ctx context.Context, query string) error {
	if query == "" {
		s.printf("search needs some text\n")
		return nil
	}
	results, err := s.index.Search(ctx, query)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		s.printf("no matches\n")
		return nil
	}
	// The ranking names the embedder that produced it. A lexical ranking
	// presented as a semantic one would be a claim this client cannot support.
	s.printf("%d %s (%s ranking)\n", len(results), plural(len(results), "match", "matches"),
		results[0].Provenance)
	for _, result := range results {
		s.printf("%s  %-40s  lexical %3d  basin %.2f\n",
			result.Object.ID[:shortID], truncateTitle(result.Object.Document.Title),
			result.Lexical, result.Semantic)
	}
	return nil
}

func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

func truncateTitle(title string) string {
	const width = 40
	runes := []rune(title)
	if len(runes) <= width {
		return title
	}
	return string(runes[:width-1]) + "…"
}

func (s *session) read(prefix string) {
	if prefix == "" {
		s.printf("read needs an object id\n")
		return
	}
	matches := make([]objectstore.Object, 0, 2)
	for _, object := range s.objects {
		if strings.HasPrefix(object.ID, strings.ToLower(prefix)) {
			matches = append(matches, object)
		}
	}
	sort.Slice(matches, func(a, b int) bool { return matches[a].ID < matches[b].ID })
	switch len(matches) {
	case 0:
		s.printf("no object with id prefix %q\n", prefix)
		return
	case 1:
	default:
		// An ambiguous prefix renders nothing rather than the first match:
		// picking one silently is how a reader ends up reading a different
		// object than the one they named.
		s.printf("%q matches %d objects:\n", prefix, len(matches))
		for _, object := range matches {
			s.printf("  %s  %s\n", object.ID[:shortID], object.Document.Title)
		}
		return
	}

	object := matches[0]
	document := object.Document
	s.printf("\n%s\n", document.Title)
	s.printf("%s, %s  |  publisher %s\n", document.PublisherName, document.PublishedAt,
		object.PublisherFingerprint)
	if len(document.Tags) > 0 {
		s.printf("tags: %s\n", strings.Join(document.Tags, ", "))
	}
	if document.Summary != "" {
		s.printf("\n%s\n", document.Summary)
	}
	// Rendered as the media type the signature covers, which is the only one
	// this client renders at all.
	s.printf("\n%s\n\n", document.Body)
}

// status reports the last rescan.
//
// A rescan is not announced when it happens: a line arriving in the middle of
// someone typing is noise. But a rescan that failed and said nothing would
// leave a reader looking at a stale corpus with no way to tell, so the record
// is kept and shown on request.
func (s *session) status() {
	s.mutex.RLock()
	last := s.last
	objects := len(s.objects)
	s.mutex.RUnlock()

	s.printf("%d verified objects, %d searchable\n", objects, s.index.Len())
	if !last.ran {
		s.printf("no rescan yet; the directory was read once at startup\n")
		return
	}
	if last.err != nil {
		s.printf("last rescan at %s failed: %v\n",
			last.at.UTC().Format(time.RFC3339), last.err)
		return
	}
	s.printf("last rescan at %s: %d verified, %d added, %d removed\n",
		last.at.UTC().Format(time.RFC3339), last.verified, last.added, last.removed)
	if last.rejected > 0 {
		s.printf("%d files in the object directory did not verify\n", last.rejected)
	}
	if last.failed > 0 {
		s.printf("%d verified objects could not be indexed and are not searchable\n", last.failed)
	}
}
