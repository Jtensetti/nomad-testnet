package dkgnet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const resultVoteVersion = "nomad-dkg-result-vote-v1"

type resultVote struct {
	Version        string                `json:"version"`
	ManifestDigest string                `json:"manifest_digest"`
	Attestation    committee.Attestation `json:"attestation"`
}

func encodeResultVote(manifest committee.Manifest, attestation committee.Attestation) ([]byte, error) {
	digest, err := committee.ManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(resultVote{Version: resultVoteVersion, ManifestDigest: hex.EncodeToString(digest[:]), Attestation: attestation})
}

func decodeResultVote(encoded []byte, sender topology.Operator, expected [32]byte) (committee.Attestation, error) {
	var vote resultVote
	if err := strictJSON(encoded, &vote); err != nil {
		return committee.Attestation{}, err
	}
	if vote.Version != resultVoteVersion || vote.ManifestDigest != hex.EncodeToString(expected[:]) || vote.Attestation.OperatorID != sender.ID || vote.Attestation.Index != uint32(sender.Index) {
		return committee.Attestation{}, errors.New("DKG result vote context mismatch")
	}
	canonical, err := json.Marshal(vote)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return committee.Attestation{}, errors.New("DKG result vote encoding is not canonical")
	}
	return vote.Attestation, nil
}
