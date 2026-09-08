package telemetry

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Scanner looks for known-secret VALUES in anything a process emits.
//
// The schema constrains field names; this constrains content. They catch
// different mistakes, and the one this catches is the more common: a field
// that is legitimately published carrying something that is not. Registering
// the actual secrets a run used and then scanning everything it wrote is a
// direct test rather than a heuristic -- there is no guessing about what
// "looks sensitive".
type Scanner struct {
	needles map[string]string
}

// Finding is one secret located in emitted output.
type Finding struct {
	Label    string
	Encoding string
	Offset   int
}

func NewScanner() *Scanner {
	return &Scanner{needles: make(map[string]string)}
}

// Register adds a secret to look for, under a label naming what it is.
//
// Each secret is registered in every encoding a process might plausibly write
// it in. A raw key never appears verbatim in a JSON file, but its hex or
// base64 rendering does, and a scanner that only looked for the raw bytes
// would report a clean run over a file containing the key in hex.
func (scanner *Scanner) Register(label string, secret []byte) {
	if len(secret) == 0 {
		return
	}
	scanner.add(label, "raw", string(secret))
	scanner.add(label, "hex", hex.EncodeToString(secret))
	scanner.add(label, "HEX", strings.ToUpper(hex.EncodeToString(secret)))
	scanner.add(label, "base64", base64.StdEncoding.EncodeToString(secret))
	scanner.add(label, "base64url", base64.URLEncoding.EncodeToString(secret))
	scanner.add(label, "base64raw", base64.RawStdEncoding.EncodeToString(secret))
}

// RegisterString adds a secret that is already text, such as a query.
func (scanner *Scanner) RegisterString(label, secret string) {
	if secret == "" {
		return
	}
	scanner.add(label, "text", secret)
}

func (scanner *Scanner) add(label, encoding, needle string) {
	// Very short needles would match by chance and make the scanner useless.
	if len(needle) < 8 {
		return
	}
	scanner.needles[needle] = label + " (" + encoding + ")"
}

// Scan reports every registered secret found in the data.
func (scanner *Scanner) Scan(data []byte) []Finding {
	haystack := string(data)
	findings := make([]Finding, 0)
	for needle, label := range scanner.needles {
		if offset := strings.Index(haystack, needle); offset >= 0 {
			parts := strings.SplitN(label, " (", 2)
			encoding := strings.TrimSuffix(parts[len(parts)-1], ")")
			findings = append(findings, Finding{Label: parts[0], Encoding: encoding, Offset: offset})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Label != findings[j].Label {
			return findings[i].Label < findings[j].Label
		}
		return findings[i].Encoding < findings[j].Encoding
	})
	return findings
}

// Registered reports how many distinct byte patterns the scanner is looking
// for. A scan that finds nothing means nothing if it was looking for nothing,
// so callers assert on this before trusting a clean result.
func (scanner *Scanner) Registered() int { return len(scanner.needles) }

func (finding Finding) String() string {
	return fmt.Sprintf("%s as %s at offset %d", finding.Label, finding.Encoding, finding.Offset)
}
