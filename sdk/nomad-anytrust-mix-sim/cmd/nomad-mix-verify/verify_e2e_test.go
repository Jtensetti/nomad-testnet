package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

// What is needed is a third-party verification tool. A library function that a
// third party could call is not one: it needs a Go toolchain, an import path
// and a program somebody has to write. What is tested here is the thing an
// outsider actually runs -- a compiled binary, given a file and a list of keys.
//
// The binary is built and executed rather than its run() called, because the
// gap between "the package works" and "the command works" is where a flag name,
// an exit code or an argument parser goes wrong, and that gap is exactly what a
// third party hits first.

func buildVerifier(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "nomad-mix-verify")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	return binary
}

// publishTranscript runs a real committee and writes what it published.
func publishTranscript(t *testing.T, mixers int) (path string, keys []string) {
	t.Helper()
	encryptionKey, _, err := mix.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]mix.PlainCell, 4)
	for index := range plain {
		copy(plain[index][:], "publication fragment")
		plain[index][0] = byte(index + 1)
	}
	batch, err := mix.Encrypt(encryptionKey, plain)
	if err != nil {
		t.Fatal(err)
	}

	context := mix.RoundContext{Epoch: 9}
	copy(context.CommitteeID[:], "third-party-committee")

	var rounds []mix.Round
	var receipts []mix.RoundReceipt
	current := batch
	for index := 0; index < mixers; index++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := current.Digest()
		if err != nil {
			t.Fatal(err)
		}
		roundContext := context
		roundContext.Round = uint32(index)
		roundContext.BatchID = digest
		output, proof, receipt, err := mix.ShuffleAndSign(roundContext, encryptionKey, current, private)
		if err != nil {
			t.Fatal(err)
		}
		rounds = append(rounds, mix.Round{Input: current, Output: output, Proof: proof})
		receipts = append(receipts, receipt)
		keys = append(keys, hex.EncodeToString(public))
		current = output
	}

	transcript, err := mix.ExportTranscript(encryptionKey, context, rounds, receipts)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mix.MarshalTranscript(transcript)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "transcript.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, keys
}

func TestTheVerifierAcceptsAPublishedTranscript(t *testing.T) {
	binary := buildVerifier(t)
	path, keys := publishTranscript(t, 3)

	command := exec.Command(binary, "-transcript", path, "-mixers", strings.Join(keys, ","))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the verifier refused a transcript a committee produced: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "VERIFIED") {
		t.Fatalf("no verdict in the output:\n%s", output)
	}
	// The tool must say what a pass means. A verifier that prints only
	// "VERIFIED" invites the reading that unlinkability was checked.
	if !strings.Contains(string(output), "does not establish unlinkability") {
		t.Errorf("the verifier does not state the limit of what it checked:\n%s", output)
	}
}

func TestTheVerifierRefusesAndExitsNonZero(t *testing.T) {
	binary := buildVerifier(t)
	path, keys := publishTranscript(t, 3)

	stranger, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one character inside a base64 proof. The file stays valid JSON, so
	// what refuses it is the proof rather than the parser.
	index := strings.Index(string(original), `"proof": "`) + len(`"proof": "`)
	altered := []byte(string(original))
	if altered[index] == 'A' {
		altered[index] = 'B'
	} else {
		altered[index] = 'A'
	}
	if err := os.WriteFile(tampered, altered, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]string{
		"a tampered proof": {"-transcript", tampered, "-mixers", strings.Join(keys, ",")},
		"a stranger's key": {"-transcript", path, "-mixers", hex.EncodeToString(stranger) + "," + keys[1] + "," + keys[2]},
		"too few keys":     {"-transcript", path, "-mixers", keys[0]},
		"no keys":          {"-transcript", path},
		"no transcript":    {"-mixers", strings.Join(keys, ",")},
		"a missing file":   {"-transcript", filepath.Join(t.TempDir(), "absent.json"), "-mixers", strings.Join(keys, ",")},
	}
	for name, arguments := range cases {
		t.Run(name, func(t *testing.T) {
			command := exec.Command(binary, arguments...)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("the verifier accepted %s:\n%s", name, output)
			}
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() == 0 {
				t.Fatalf("%s did not produce a non-zero exit status: %v", name, err)
			}
			if strings.Contains(string(output), "VERIFIED") {
				t.Fatalf("%s printed a verdict of VERIFIED:\n%s", name, output)
			}
		})
	}
}
