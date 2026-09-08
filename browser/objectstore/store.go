package objectstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Extension is the suffix of a materialized object in the local cache.
const Extension = ".nomadobject"

// MaxObjects bounds how many files one scan will read. A cache directory that
// has been filled with entries is a local denial-of-service at worst, never an
// unbounded read.
const MaxObjects = 256

// Result is one scan of the object directory.
//
// Rejected counts files that did not verify. It is reported rather than logged
// away because a client that silently renders fewer objects than it has looks
// exactly like a client that has been given fewer objects.
type Result struct {
	Objects  []Object
	Rejected int
}

// Load reads every .nomadobject file in directory and returns those that
// verify against trusted, sorted by title.
//
// One malformed or hostile file must not suppress the rest, so a file that
// fails is counted and skipped. A directory that cannot be read at all is an
// error: that is a different condition from "no objects", and collapsing the
// two would hide a misconfigured cache path behind an empty result.
func Load(directory string, trusted TrustSet) (Result, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return Result{}, fmt.Errorf("reading the object directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, Extension) {
			continue
		}
		// Type comes from the directory read itself, so a symlink is skipped
		// without ever being opened. A cache directory is not a place to
		// follow a link out of: the link target is chosen by whoever wrote the
		// directory, not by whoever signed the object.
		if !entry.Type().IsRegular() {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > MaxObjects {
		names = names[:MaxObjects]
	}

	result := Result{}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		object, err := loadOne(filepath.Join(directory, name), trusted)
		if err != nil {
			result.Rejected++
			continue
		}
		// Two files carrying the same object are one object. The ID is the
		// commitment, so this deduplicates on content rather than on filename.
		if _, duplicate := seen[object.ID]; duplicate {
			continue
		}
		seen[object.ID] = struct{}{}
		result.Objects = append(result.Objects, object)
	}
	sort.Slice(result.Objects, func(a, b int) bool {
		if result.Objects[a].Document.Title != result.Objects[b].Document.Title {
			return result.Objects[a].Document.Title < result.Objects[b].Document.Title
		}
		return result.Objects[a].ID < result.Objects[b].ID
	})
	return result, nil
}

func loadOne(path string, trusted TrustSet) (Object, error) {
	file, err := os.Open(path)
	if err != nil {
		return Object{}, err
	}
	defer file.Close()

	// Stat through the open handle, so the file measured is the file read even
	// if the path was replaced between the directory scan and the open.
	info, err := file.Stat()
	if err != nil {
		return Object{}, err
	}
	if !info.Mode().IsRegular() {
		return Object{}, errors.New("object is not a regular file")
	}
	if info.Size() > MaxEncodedEnvelopeBytes {
		return Object{}, ErrObjectTooLarge
	}

	// One byte past the limit is still read, so that a file which grew between
	// the stat and the read is refused rather than silently truncated into
	// something that parses.
	data, err := io.ReadAll(io.LimitReader(file, MaxEncodedEnvelopeBytes+1))
	if err != nil {
		return Object{}, err
	}
	if len(data) > MaxEncodedEnvelopeBytes {
		return Object{}, ErrObjectTooLarge
	}

	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Object{}, ErrMalformedEncoding
	}
	return Verify(envelope, trusted)
}
