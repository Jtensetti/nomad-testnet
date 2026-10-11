package main

import (
	"encoding/hex"
	"errors"
	"strings"
)

// decodeFixed reads a hex value of an exact length. The length is checked
// rather than inferred, so a truncated key file fails here instead of
// producing a shorter secret that would still derive a session.
func decodeFixed(encoded []byte, size int) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, errors.New("value is not hex")
	}
	if len(decoded) != size {
		return nil, errors.New("value is not the expected length")
	}
	return decoded, nil
}
