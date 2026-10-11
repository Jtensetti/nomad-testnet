package strictjson

import (
	"encoding/base64"
	"errors"
)

// DecodeBase64 decodes standard base64 that has exactly one encoding.
//
// Go's decoder ignores \r and \n wherever they appear, and Strict() does not
// change that: it constrains the final quantum's padding bits and nothing
// else. So "AAAA" and "AA\nAA" decode to the same bytes, and any document
// carrying a base64 field has as many encodings as there are places to put a
// newline in it.
//
// That is the same ambiguity as a duplicate key, arriving through a different
// door, and it is invisible in the same way. Where the field is part of what
// is signed, re-serialising catches it -- the canonical form differs, so the
// signature fails. Where the field is excluded from what is signed, nothing
// catches it: a topology's own authority signature is not covered by the
// signature, so a newline inside it is accepted here and refused by the
// Python reference, which decodes with validate=True. The two implementations
// then disagree about whether a topology is valid, which is a split view of
// the operator set created by whoever distributes the file.
//
// Callers reading a key out of a file should trim the surrounding whitespace
// before calling this: a trailing newline in a file is not an encoding of the
// key, and a file is not a document another implementation parses.
func DecodeBase64(encoded string) ([]byte, error) {
	for index := 0; index < len(encoded); index++ {
		if !isBase64Alphabet(encoded[index]) {
			return nil, errors.New("base64 field contains a character outside the alphabet")
		}
	}
	return base64.StdEncoding.Strict().DecodeString(encoded)
}

func isBase64Alphabet(character byte) bool {
	switch {
	case character >= 'A' && character <= 'Z',
		character >= 'a' && character <= 'z',
		character >= '0' && character <= '9',
		character == '+', character == '/', character == '=':
		return true
	}
	return false
}
