package epoch

import (
	"strings"
	"testing"
)

func TestLifecycleDecodersRejectDuplicateJSONKeys(t *testing.T) {
	encoded := []byte(`{"version":"first","version":"second"}`)
	tests := []struct {
		name   string
		decode func([]byte) error
	}{
		{"epoch descriptor", func(value []byte) error { _, err := decodeDescriptor(value); return err }},
		{"revocation", func(value []byte) error { _, err := DecodeRevocation(value); return err }},
		{"erasure statement", func(value []byte) error { _, err := DecodeErasureStatement(value); return err }},
		{"erasure intent", func(value []byte) error { _, err := DecodeErasureIntent(value); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.decode(encoded)
			if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
				t.Fatalf("duplicate key was not rejected as ambiguity: %v", err)
			}
		})
	}
}
