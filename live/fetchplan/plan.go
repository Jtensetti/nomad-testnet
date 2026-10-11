// Package fetchplan verifies the minimal public plan used by the fixed-rate
// partial fetcher. It deliberately contains no object, query or reconstruction
// metadata.
package fetchplan

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/Jtensetti/nomad-testnet/live/hop"
	"github.com/Jtensetti/nomad-testnet/live/strictjson"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	Version          = "nomad-partial-fetch-plan-v1"
	MaximumFileBytes = 16 << 10
)

type Plan struct {
	Version            string `json:"version"`
	NetworkID          string `json:"network_id"`
	TopologyEpoch      uint64 `json:"topology_epoch"`
	TopologyDigest     string `json:"topology_digest"`
	StreamID           string `json:"stream_id"`
	AuthoritySignature string `json:"authority_signature"`
}

func Sign(plan Plan, authority ed25519.PrivateKey) (Plan, error) {
	if len(authority) != ed25519.PrivateKeySize {
		return Plan{}, errors.New("fetch-plan authority private key is invalid")
	}
	plan.AuthoritySignature = ""
	canonical, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, err
	}
	message := append([]byte("nomad-partial-fetch-plan-authority-v1"), canonical...)
	plan.AuthoritySignature = base64.StdEncoding.EncodeToString(ed25519.Sign(authority, message))
	return plan, nil
}

func Encode(plan Plan) ([]byte, error) { return json.MarshalIndent(plan, "", "  ") }

func Load(path string, authority ed25519.PublicKey, network topology.Verified) (Plan, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Plan{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumFileBytes {
		return Plan{}, errors.New("fetch plan must be a bounded regular file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return Plan{}, err
	}
	return Verify(encoded, authority, network)
}

func Verify(encoded []byte, authority ed25519.PublicKey, network topology.Verified) (Plan, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes || len(authority) != ed25519.PublicKeySize {
		return Plan{}, errors.New("fetch plan input is invalid")
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, errors.New("trailing fetch-plan data")
	}
	signature, err := strictjson.DecodeBase64(plan.AuthoritySignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Plan{}, errors.New("fetch-plan signature encoding is invalid")
	}
	unsigned := plan
	unsigned.AuthoritySignature = ""
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return Plan{}, err
	}
	message := append([]byte("nomad-partial-fetch-plan-authority-v1"), canonical...)
	if !ed25519.Verify(authority, message, signature) {
		return Plan{}, errors.New("fetch-plan authority signature verification failed")
	}
	if plan.Version != Version || plan.NetworkID != network.Document.NetworkID ||
		plan.TopologyEpoch != network.Document.Epoch || plan.TopologyDigest != hex.EncodeToString(network.Digest[:]) {
		return Plan{}, errors.New("fetch plan belongs to a different topology")
	}
	stream, err := hex.DecodeString(plan.StreamID)
	if err != nil || len(stream) != len(hop.StreamID{}) || plan.StreamID != hex.EncodeToString(stream) {
		return Plan{}, errors.New("fetch-plan stream ID is invalid")
	}
	return plan, nil
}
