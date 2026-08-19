package batch

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

func committeeToFile(committee mix.ThresholdCommittee) CommitteeFile {
	members := make([]MemberFile, len(committee.Members))
	for index, member := range committee.Members {
		members[index] = MemberFile{
			Index: member.Index,
			Share: base64.StdEncoding.EncodeToString(member.Share[:]),
		}
	}
	return CommitteeFile{
		ID:        hex.EncodeToString(committee.ID[:]),
		Epoch:     committee.Epoch,
		Threshold: committee.Threshold,
		PublicKey: base64.StdEncoding.EncodeToString(committee.PublicKey[:]),
		Members:   members,
	}
}

func (file CommitteeFile) toMix() (mix.ThresholdCommittee, error) {
	id, err := decodeHex(file.ID, len(mix.CommitteeID{}))
	if err != nil {
		return mix.ThresholdCommittee{}, errors.New("invalid committee ID")
	}
	publicKey, err := decodeBase64(file.PublicKey, len(mix.PublicKey{}))
	if err != nil {
		return mix.ThresholdCommittee{}, errors.New("invalid committee public key")
	}
	committee := mix.ThresholdCommittee{
		Epoch: file.Epoch, Threshold: file.Threshold, Members: make([]mix.PublicMember, len(file.Members)),
	}
	copy(committee.ID[:], id)
	copy(committee.PublicKey[:], publicKey)
	for index, memberFile := range file.Members {
		share, err := decodeBase64(memberFile.Share, len(mix.SharePublicKey{}))
		if err != nil {
			return mix.ThresholdCommittee{}, fmt.Errorf("invalid committee member %d share", index)
		}
		committee.Members[index].Index = memberFile.Index
		copy(committee.Members[index].Share[:], share)
	}
	return committee, nil
}

func transcriptToFile(transcript mix.DKGTranscript) DKGTranscriptFile {
	identities := make([]string, len(transcript.Identities))
	for index, identity := range transcript.Identities {
		identities[index] = base64.StdEncoding.EncodeToString(identity[:])
	}
	return DKGTranscriptFile{
		SessionID: hex.EncodeToString(transcript.SessionID[:]),
		Digest: hex.EncodeToString(transcript.Digest[:]),
		Identities: identities,
		Qualified: append([]uint32(nil), transcript.Qualified...),
	}
}

func (file DKGTranscriptFile) toMix(memberCount int) (mix.DKGTranscript, error) {
	session, err := decodeHex(file.SessionID, 32)
	if err != nil {
		return mix.DKGTranscript{}, errors.New("invalid DKG session ID")
	}
	digest, err := decodeHex(file.Digest, 32)
	if err != nil {
		return mix.DKGTranscript{}, errors.New("invalid DKG transcript digest")
	}
	if len(file.Identities) != memberCount || len(file.Qualified) < 2 || len(file.Qualified) > memberCount {
		return mix.DKGTranscript{}, errors.New("invalid DKG transcript membership")
	}
	transcript := mix.DKGTranscript{
		Identities: make([]mix.SharePublicKey, len(file.Identities)),
		Qualified: append([]uint32(nil), file.Qualified...),
	}
	copy(transcript.SessionID[:], session)
	copy(transcript.Digest[:], digest)
	seen := make(map[uint32]struct{}, len(file.Qualified))
	for index, encoded := range file.Identities {
		identity, err := decodeBase64(encoded, len(mix.SharePublicKey{}))
		if err != nil {
			return mix.DKGTranscript{}, fmt.Errorf("invalid DKG identity %d", index)
		}
		copy(transcript.Identities[index][:], identity)
	}
	for _, qualified := range transcript.Qualified {
		if int(qualified) >= memberCount {
			return mix.DKGTranscript{}, errors.New("DKG qualified index is outside committee")
		}
		if _, exists := seen[qualified]; exists {
			return mix.DKGTranscript{}, errors.New("duplicate DKG qualified index")
		}
		seen[qualified] = struct{}{}
	}
	return transcript, nil
}

func receiptToFile(receipt mix.RoundReceipt) ReceiptFile {
	return ReceiptFile{
		CommitteeID: hex.EncodeToString(receipt.Context.CommitteeID[:]),
		Epoch: receipt.Context.Epoch,
		BatchID: hex.EncodeToString(receipt.Context.BatchID[:]),
		Round: receipt.Context.Round,
		MixerPublic: base64.StdEncoding.EncodeToString(receipt.MixerPublic[:]),
		InputDigest: hex.EncodeToString(receipt.InputDigest[:]),
		OutputDigest: hex.EncodeToString(receipt.OutputDigest[:]),
		ProofDigest: hex.EncodeToString(receipt.ProofDigest[:]),
		Signature: base64.StdEncoding.EncodeToString(receipt.Signature[:]),
	}
}

func (file ReceiptFile) toMix() (mix.RoundReceipt, error) {
	committeeID, err := decodeHex(file.CommitteeID, len(mix.CommitteeID{}))
	if err != nil {
		return mix.RoundReceipt{}, errors.New("invalid receipt committee ID")
	}
	batchID, err := decodeHex(file.BatchID, 32)
	if err != nil {
		return mix.RoundReceipt{}, errors.New("invalid receipt batch ID")
	}
	mixerPublic, err := decodeBase64(file.MixerPublic, 32)
	if err != nil {
		return mix.RoundReceipt{}, errors.New("invalid receipt mixer key")
	}
	inputDigest, err := decodeHex(file.InputDigest, 32)
	if err != nil {
		return mix.RoundReceipt{}, errors.New("invalid receipt input digest")
	}
	outputDigest, err := decodeHex(file.OutputDigest, 32)
	if err != nil {
		return mix.RoundReceipt{}, errors.New("invalid receipt output digest")
	}
	proofDigest, err := decodeHex(file.ProofDigest, 32)
	if err != nil {
		return mix.RoundReceipt{}, errors.New("invalid receipt proof digest")
	}
	signature, err := decodeBase64(file.Signature, 64)
	if err != nil {
		return mix.RoundReceipt{}, errors.New("invalid receipt signature")
	}
	receipt := mix.RoundReceipt{Context: mix.RoundContext{Epoch: file.Epoch, Round: file.Round}}
	copy(receipt.Context.CommitteeID[:], committeeID)
	copy(receipt.Context.BatchID[:], batchID)
	copy(receipt.MixerPublic[:], mixerPublic)
	copy(receipt.InputDigest[:], inputDigest)
	copy(receipt.OutputDigest[:], outputDigest)
	copy(receipt.ProofDigest[:], proofDigest)
	copy(receipt.Signature[:], signature)
	return receipt, nil
}
