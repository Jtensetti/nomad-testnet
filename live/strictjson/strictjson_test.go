package strictjson

import (
	"strings"
	"testing"
)

func TestRejectsDuplicateKeysAnywhere(t *testing.T) {
	for name, document := range map[string]string{
		"top level":          `{"a":1,"a":2}`,
		"nested object":      `{"outer":{"b":1,"b":2}}`,
		"inside an array":    `{"list":[{"c":1,"c":2}]}`,
		"deeply nested":      `{"a":{"b":{"c":[[{"d":1,"d":1}]]}}}`,
		"null then value":    `{"document":null,"document":{"x":1}}`,
		"repeated third key": `{"a":1,"b":2,"a":3}`,
	} {
		if err := RejectDuplicateKeys([]byte(document)); err == nil {
			t.Fatalf("%s: duplicate key accepted", name)
		} else if !strings.Contains(err.Error(), "duplicate JSON key") {
			t.Fatalf("%s: refused for the wrong reason: %v", name, err)
		}
	}
}

func TestAcceptsUnambiguousDocuments(t *testing.T) {
	for name, document := range map[string]string{
		"flat":                    `{"a":1,"b":2}`,
		"same key at two depths":  `{"a":1,"nested":{"a":2}}`,
		"same key in two objects": `{"list":[{"a":1},{"a":2}]}`,
		"empty object":            `{}`,
		"empty array":             `[]`,
		"scalar":                  `42`,
		"string":                  `"nomad"`,
		"null":                    `null`,
		"whitespace around":       "  \n{\"a\":1}\t ",
		"nested arrays":           `{"a":[[1,2],[3,4]]}`,
	} {
		if err := RejectDuplicateKeys([]byte(document)); err != nil {
			t.Fatalf("%s: unambiguous document refused: %v", name, err)
		}
	}
}

func TestRejectsMalformedAndMultipleDocuments(t *testing.T) {
	for name, document := range map[string]string{
		"truncated object": `{"a":1`,
		"two documents":    `{"a":1}{"b":2}`,
		"trailing value":   `{"a":1} 7`,
		"not json":         `nomad`,
		"empty":            ``,
	} {
		if err := RejectDuplicateKeys([]byte(document)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
