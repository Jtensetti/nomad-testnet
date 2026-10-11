package telemetry

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAllowlistRejectsUnknownFields(t *testing.T) {
	valid := map[string]any{}
	for _, field := range Allowed() {
		valid[field.Name] = 1
	}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEmission(encoded); err != nil {
		t.Fatalf("the allowlist rejects its own fields: %v", err)
	}

	// A field nobody thought about is the case that matters: it must fail
	// rather than pass for want of a rule against it.
	valid["objects_served_by_basin"] = 3
	encoded, _ = json.Marshal(valid)
	if err := ValidateEmission(encoded); !errors.Is(err, ErrFieldNotAllowed) {
		t.Errorf("an unlisted field was accepted: %v", err)
	}
}

// Each of these is a counter that exists in the codebase and is deliberately
// operator-local. Emitting any of them would publish exactly what a mechanism
// elsewhere exists to hide.
func TestForbiddenFieldsAreNamedWithTheirReason(t *testing.T) {
	traps := []string{
		"pending", "dropped_full", "dropped_session", "real_deposits",
		"object_id", "basin", "queries", "share", "session_key", "deposit_id",
	}
	for _, name := range traps {
		why, banned := ForbiddenReason(name)
		if !banned {
			t.Errorf("%q is not recorded as forbidden", name)
			continue
		}
		if why == "" {
			t.Errorf("%q is forbidden with no reason given", name)
		}
		encoded, _ := json.Marshal(map[string]any{name: 1})
		err := ValidateEmission(encoded)
		if !errors.Is(err, ErrFieldNotAllowed) {
			t.Errorf("%q was accepted: %v", name, err)
		}
		if !strings.Contains(err.Error(), why) {
			t.Errorf("%q was rejected without explaining why: %v", name, err)
		}
	}
}

func TestEveryAllowedFieldRecordsWhyItIsPublic(t *testing.T) {
	for _, field := range Allowed() {
		if strings.TrimSpace(field.Why) == "" {
			t.Errorf("%q is allowed with no stated reason", field.Name)
		}
		if _, banned := ForbiddenReason(field.Name); banned {
			t.Errorf("%q is both allowed and forbidden", field.Name)
		}
	}
}

func TestScannerFindsSecretsInEveryEncodingAProcessMightUse(t *testing.T) {
	secret := []byte("this-is-a-threshold-share-000001")
	scanner := NewScanner()
	scanner.Register("threshold share", secret)
	if scanner.Registered() < 5 {
		t.Fatalf("only %d encodings registered", scanner.Registered())
	}

	// A raw key rarely appears verbatim in JSON, but its hex or base64
	// rendering does, and a scanner blind to those reports a clean run over a
	// file that contains the key.
	for _, rendering := range []string{
		string(secret),
		"{\"note\":\"" + toHex(secret) + "\"}",
		"{\"note\":\"" + toBase64(secret) + "\"}",
	} {
		findings := scanner.Scan([]byte(rendering))
		if len(findings) == 0 {
			t.Errorf("no finding in %.40s...", rendering)
		}
	}

	if findings := scanner.Scan([]byte(`{"sent":128,"cover_sent":128}`)); len(findings) != 0 {
		t.Errorf("clean telemetry produced findings: %v", findings)
	}
}

func TestScannerIgnoresNeedlesTooShortToBeMeaningful(t *testing.T) {
	scanner := NewScanner()
	scanner.Register("tiny", []byte("ab"))
	scanner.RegisterString("tiny text", "xy")
	if scanner.Registered() != 0 {
		t.Errorf("short needles were registered and would match by chance")
	}
}

func toHex(data []byte) string    { return hex.EncodeToString(data) }
func toBase64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }
