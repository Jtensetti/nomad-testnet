// Command nomad-mix-verify checks a published committee transcript.
//
// It exists so that "individually verifiable" is something a person outside the
// committee can act on rather than a property of the code. It takes a
// transcript and the committee's published identity keys, and it answers one
// question: does every round's proof and receipt check out, and do the rounds
// join into a chain.
//
// It holds no key, opens no socket and needs no membership. The committee's
// identity keys are supplied separately rather than read from the transcript,
// because a transcript that named its own signers would authenticate nothing.
//
// What a passing verdict means, and it is worth being exact: each round's
// output is a re-randomised permutation of its input, signed by the mixer the
// caller named for that position. That is correctness. It is not unlinkability,
// which needs one honest mixer and cannot be shown by any transcript -- a
// committee that colluded end to end would publish a transcript that verifies.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"crypto/ed25519"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "REFUSED:", err)
		os.Exit(1)
	}
}

func run() error {
	transcriptPath := flag.String("transcript", "", "path to the published committee transcript")
	mixerKeys := flag.String("mixers", "",
		"comma-separated committee identity public keys, in round order, hex or base64")
	flag.Parse()

	if *transcriptPath == "" || *mixerKeys == "" {
		flag.Usage()
		return errors.New("both -transcript and -mixers are required")
	}
	encoded, err := os.ReadFile(*transcriptPath)
	if err != nil {
		return err
	}
	transcript, err := mix.UnmarshalTranscript(encoded)
	if err != nil {
		return fmt.Errorf("read transcript: %w", err)
	}
	mixers, err := parseMixerKeys(*mixerKeys)
	if err != nil {
		return err
	}
	if err := mix.VerifyTranscript(transcript, mixers); err != nil {
		return err
	}
	fmt.Printf("VERIFIED: %d round(s), committee %s, epoch %d\n",
		len(transcript.Rounds), transcript.CommitteeID, transcript.Epoch)
	fmt.Println("This establishes that each round's output is a re-randomised permutation " +
		"of its input, signed by the mixer named for that position. It does not " +
		"establish unlinkability, which needs one honest mixer and which no transcript " +
		"can show.")
	return nil
}

func parseMixerKeys(list string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for index, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		raw, err := hex.DecodeString(field)
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(field)
			if err != nil {
				return nil, fmt.Errorf("mixer key %d is neither hex nor base64", index)
			}
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("mixer key %d is %d bytes, not %d",
				index, len(raw), ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil, errors.New("no mixer keys were supplied, so nothing could be authenticated")
	}
	return keys, nil
}
