package topology

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The topology is what every other check in the system is relative to, and a
// signature over it is a signature over specific bytes. Those bytes used to be
// whatever Go's encoding/json produced for these structs, which is not a
// specification:
//
//   - members came out in struct-declaration order, so adding a field in the
//     middle of a struct would have changed the signed bytes of documents that
//     did not otherwise change;
//   - `<`, `>` and `&` came out as <, > and &, which no JSON
//     specification requires and which only Go does by default. It is
//     invisible until a network identifier or an endpoint contains an
//     ampersand, at which point a second implementation computes a different
//     digest for the same document and nobody can tell why;
//   - an absent array came out as null rather than [].
//
// A canonical encoding defined by one language's library defaults cannot be
// frozen. This is the encoding written down instead, close to RFC 8785 (JCS)
// and deliberately stricter in one place: every number in a Nomad signed
// document is an integer, so a fractional or exponential literal is refused
// rather than given a canonical form. That removes the whole floating-point
// half of JCS, which is where its subtleties live.

// canonicalJSON re-emits one JSON value in Nomad's canonical form:
//
//   - object members sorted by the UTF-16 code units of their names;
//   - no whitespace between tokens;
//   - strings escaped minimally -- only ", \ and the control characters, with
//     the short forms where they exist and lowercase \u00xx otherwise;
//   - integers as their exact decimal digits, with no exponent and no
//     leading zeros or plus sign;
//   - an absent array as [], never null.
//
// The input is always this package's own encoding/json output, so it cannot
// contain duplicate member names.
func canonicalJSON(encoded []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("canonical encoding: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("canonical encoding: trailing content after the value")
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		// A nil slice reaches here as null. Nomad documents have no nullable
		// fields, so this is an absent array and encodes as one.
		out.WriteString("[]")
		return nil
	case bool:
		if typed {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
		return nil
	case json.Number:
		return writeCanonicalNumber(out, typed)
	case string:
		return writeCanonicalString(out, typed)
	case []any:
		out.WriteByte('[')
		for index, element := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, element); err != nil {
				return err
			}
		}
		out.WriteByte(']')
		return nil
	case map[string]any:
		names := make([]string, 0, len(typed))
		for name := range typed {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool {
			return lessUTF16(names[i], names[j])
		})
		out.WriteByte('{')
		for index, name := range names {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonicalString(out, name); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writeCanonical(out, typed[name]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonical encoding: unsupported value of type %T", value)
	}
}

// writeCanonicalNumber refuses anything that is not an integer literal.
//
// Every number in a Nomad signed document is an integer -- an epoch, a count,
// a threshold, a millisecond interval. Refusing the rest means this encoding
// never has to decide what the canonical form of 1e2 or 1.10 is, which is the
// part of JSON canonicalization that implementations get wrong.
func writeCanonicalNumber(out *bytes.Buffer, number json.Number) error {
	literal := number.String()
	if literal == "" {
		return errors.New("canonical encoding: empty number")
	}
	body := strings.TrimPrefix(literal, "-")
	if body == "" {
		return fmt.Errorf("canonical encoding: %q is not an integer", literal)
	}
	for _, digit := range body {
		if digit < '0' || digit > '9' {
			return fmt.Errorf("canonical encoding: %q is not an integer; Nomad signed "+
				"documents carry no fractional or exponential numbers", literal)
		}
	}
	if len(body) > 1 && body[0] == '0' {
		return fmt.Errorf("canonical encoding: %q has a leading zero", literal)
	}
	if literal == "-0" {
		return errors.New("canonical encoding: negative zero has no canonical form here")
	}
	out.WriteString(literal)
	return nil
}

const hexDigits = "0123456789abcdef"

func writeCanonicalString(out *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("canonical encoding: string is not valid UTF-8")
	}
	out.WriteByte('"')
	for _, b := range []byte(value) {
		switch b {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if b < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[b>>4])
				out.WriteByte(hexDigits[b&0x0f])
				continue
			}
			// Everything else, including every non-ASCII byte, is written
			// literally. Go escapes <, > and & by default and no JSON
			// specification asks for it.
			out.WriteByte(b)
		}
	}
	out.WriteByte('"')
	return nil
}

// lessUTF16 orders member names by their UTF-16 code units, which is what
// RFC 8785 specifies. For the ASCII names Nomad uses this is byte order; it is
// implemented properly anyway, because a specification that happens to be
// right for the current field names is not a specification.
func lessUTF16(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}
