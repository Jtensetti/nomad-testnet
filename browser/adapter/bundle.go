package adapter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"sort"
	"strings"

	"github.com/Jtensetti/nomad-browser/egress"
)

const (
	MaxBundleEntries = 1024
	MaxResourcePath  = egress.MaxResourcePath
	MaxMediaType     = 255
)

var bundleMagic = [5]byte{'N', 'B', 'N', 'D', 1}

type Entry struct {
	Path      string
	ObjectID  [32]byte
	MediaType string
}

type Bundle struct {
	entries map[string]Entry
}

func EncodeBundle(entries []Entry) ([]byte, error) {
	if len(entries) == 0 || len(entries) > MaxBundleEntries {
		return nil, errors.New("bundle entry count is outside the allowed range")
	}
	normalized := make([]Entry, len(entries))
	for i, entry := range entries {
		if err := validateResourcePath(entry.Path); err != nil {
			return nil, fmt.Errorf("entry %d path: %w", i, err)
		}
		mediaType, err := canonicalMediaType(entry.MediaType)
		if err != nil {
			return nil, fmt.Errorf("entry %d media type: %w", i, err)
		}
		entry.MediaType = mediaType
		normalized[i] = entry
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Path < normalized[j].Path
	})
	for i := 1; i < len(normalized); i++ {
		if normalized[i-1].Path == normalized[i].Path {
			return nil, errors.New("bundle contains duplicate resource path")
		}
	}

	var out bytes.Buffer
	_, _ = out.Write(bundleMagic[:])
	var number [2]byte
	binary.BigEndian.PutUint16(number[:], uint16(len(normalized)))
	_, _ = out.Write(number[:])
	for _, entry := range normalized {
		binary.BigEndian.PutUint16(number[:], uint16(len(entry.Path)))
		_, _ = out.Write(number[:])
		binary.BigEndian.PutUint16(number[:], uint16(len(entry.MediaType)))
		_, _ = out.Write(number[:])
		_, _ = out.Write(entry.ObjectID[:])
		_, _ = out.WriteString(entry.Path)
		_, _ = out.WriteString(entry.MediaType)
	}
	return out.Bytes(), nil
}

func ParseBundle(data []byte) (*Bundle, error) {
	if len(data) < 7 || !bytes.Equal(data[:5], bundleMagic[:]) {
		return nil, errors.New("unsupported bundle magic or version")
	}
	count := int(binary.BigEndian.Uint16(data[5:7]))
	if count == 0 || count > MaxBundleEntries {
		return nil, errors.New("bundle entry count is outside the allowed range")
	}
	offset := 7
	entries := make([]Entry, 0, count)
	for i := 0; i < count; i++ {
		if offset+36 > len(data) {
			return nil, errors.New("truncated bundle entry header")
		}
		pathLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		mediaLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		var objectID [32]byte
		copy(objectID[:], data[offset+4:offset+36])
		offset += 36
		if pathLength == 0 || mediaLength == 0 || offset+pathLength+mediaLength > len(data) {
			return nil, errors.New("invalid bundle entry lengths")
		}
		entry := Entry{
			Path:      string(data[offset : offset+pathLength]),
			ObjectID:  objectID,
			MediaType: string(data[offset+pathLength : offset+pathLength+mediaLength]),
		}
		offset += pathLength + mediaLength
		entries = append(entries, entry)
	}
	if offset != len(data) {
		return nil, errors.New("trailing bytes after bundle")
	}
	canonical, err := EncodeBundle(entries)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("bundle encoding is not canonical")
	}
	index := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		index[entry.Path] = entry
	}
	return &Bundle{entries: index}, nil
}

func (b *Bundle) Entry(resourcePath string) (Entry, bool) {
	if b == nil {
		return Entry{}, false
	}
	entry, ok := b.entries[resourcePath]
	return entry, ok
}

// validateResourcePath delegates to the shared rule so that this gate and the
// renderer URL policy cannot drift apart.
func validateResourcePath(resourcePath string) error {
	return egress.CanonicalResourcePath(resourcePath)
}

func canonicalMediaType(raw string) (string, error) {
	if raw == "" || len(raw) > MaxMediaType || strings.ContainsAny(raw, "\r\n\x00") {
		return "", errors.New("media type is empty, too long, or contains control syntax")
	}
	mediaType, parameters, err := mime.ParseMediaType(raw)
	if err != nil {
		return "", err
	}
	canonical := mime.FormatMediaType(mediaType, parameters)
	if canonical == "" || len(canonical) > MaxMediaType {
		return "", errors.New("media type cannot be represented canonically")
	}
	return canonical, nil
}
