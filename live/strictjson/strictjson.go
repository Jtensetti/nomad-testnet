// Package strictjson rejects JSON encodings that more than one parser can
// read differently.
//
// Signed documents in Nomad are verified by re-serialising what was parsed and
// checking the signature over that, so a document's identity is its canonical
// form rather than the bytes it arrived in. Reordered keys and incidental
// whitespace are therefore harmless: every parser that reads them reads the
// same document.
//
// Duplicate object keys are not. Go's encoding/json keeps the last occurrence;
// other parsers keep the first, reject, or error. A document carrying a key
// twice means different things to different implementations, so one accepts it
// and another refuses -- the two cannot agree on what was signed. That is
// exactly the ambiguity a frozen wire format must not permit, and it is
// invisible to a signature check because each implementation verifies against
// whatever it parsed.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// RejectDuplicateKeys returns an error if any JSON object in the document
// carries the same key more than once, or if the document is not a single
// well-formed JSON value.
func RejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walk(decoder, ""); err != nil {
		return err
	}
	// One value and nothing after it, so a second document cannot ride along.
	if _, err := decoder.Token(); !errorIsEOF(err) {
		return fmt.Errorf("trailing content after the JSON document")
	}
	return nil
}

func walk(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key at %q is not a string", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q at %q: the document means "+
					"different things to different parsers", key, path)
			}
			seen[key] = struct{}{}
			if err := walk(decoder, path+"/"+key); err != nil {
				return err
			}
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := walk(decoder, fmt.Sprintf("%s/%d", path, index)); err != nil {
				return err
			}
			index++
		}
	}
	// Consume the matching closing delimiter.
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return nil
}

func errorIsEOF(err error) bool { return err == io.EOF }
