package batch

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

func receiptToFile(receipt mix.RoundReceipt) ReceiptFile {
	return ReceiptFile{
		CommitteeID:  hex.EncodeToString(receipt.Context.CommitteeID[:]),
		Epoch:        receipt.Context.Epoch,
		BatchID:      hex.EncodeToString(receipt.Context.BatchID[:]),
		Round:        receipt.Context.Round,
		MixerPublic:  base64.StdEncoding.EncodeToString(receipt.MixerPublic[:]),
		InputDigest:  hex.EncodeToString(receipt.InputDigest[:]),
		OutputDigest: hex.EncodeToString(receipt.OutputDigest[:]),
		ProofDigest:  hex.EncodeToString(receipt.ProofDigest[:]),
		Signature:    base64.StdEncoding.EncodeToString(receipt.Signature[:]),
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
