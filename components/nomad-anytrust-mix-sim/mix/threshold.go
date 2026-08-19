package mix

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/proof"
	"go.dedis.ch/kyber/v4/share"
)

const (
	minCommitteeMembers = 3
	maxCommitteeMembers = 64
	thresholdProofLabel = "nomad-threshold-decryption-v1"
)

type CommitteeID [32]byte
type PrivateShare [pointSize]byte
type SharePublicKey [pointSize]byte

type PublicMember struct {
	Index uint32
	Share SharePublicKey
}

// ThresholdCommittee is public configuration for one committee epoch.
// Members are required to be ordered by their contiguous zero-based index.
type ThresholdCommittee struct {
	ID        CommitteeID
	Epoch     uint64
	Threshold uint32
	PublicKey PublicKey
	Members   []PublicMember
}

// MemberSecret is a single Shamir share. It is deliberately not serializable
// by this package. Production deployments must obtain equivalent shares from
// authenticated DKG and store them in an isolated secret service.
type MemberSecret struct {
	CommitteeID CommitteeID
	Epoch       uint64
	Index       uint32
	Secret      PrivateShare
	Public      SharePublicKey
}

// PartialDecryption contains public decryption shares and one Fiat-Shamir
// proof that the same committed member share was used for every ciphertext
// point. Points are row-major over the batch's X matrix.
type PartialDecryption struct {
	CommitteeID CommitteeID
	Epoch       uint64
	MemberIndex uint32
	BatchDigest [32]byte
	Points      [][pointSize]byte
	Proof       []byte
}

// GenerateDealerCommittee exists to exercise threshold decryption before the
// authenticated DKG protocol is integrated. It never returns the aggregate
// secret, but a trusted dealer still exists during this function. It is not a
// production key ceremony.
func GenerateDealerCommittee(id CommitteeID, epoch uint64, members, threshold uint32) (ThresholdCommittee, []MemberSecret, error) {
	if isZeroCommitteeID(id) {
		return ThresholdCommittee{}, nil, errors.New("committee ID is required")
	}
	if epoch == 0 {
		return ThresholdCommittee{}, nil, errors.New("committee epoch must be non-zero")
	}
	if members < minCommitteeMembers || members > maxCommitteeMembers {
		return ThresholdCommittee{}, nil, fmt.Errorf("committee must contain between %d and %d members", minCommitteeMembers, maxCommitteeMembers)
	}
	if threshold < 2 || threshold > members {
		return ThresholdCommittee{}, nil, errors.New("threshold must be between two and the member count")
	}

	s := newSuite()
	privatePolynomial := share.NewPriPoly(s, threshold, nil, s.RandomStream())
	privateShares := privatePolynomial.Shares(members)
	publicPolynomial := privatePolynomial.Commit(nil)
	publicShares := publicPolynomial.Shares(members)

	publicKeyBytes, err := publicPolynomial.Commit().MarshalBinary()
	if err != nil {
		return ThresholdCommittee{}, nil, err
	}
	if len(publicKeyBytes) != pointSize {
		return ThresholdCommittee{}, nil, errors.New("unexpected threshold public key size")
	}
	var publicKey PublicKey
	copy(publicKey[:], publicKeyBytes)

	committee := ThresholdCommittee{
		ID:        id,
		Epoch:     epoch,
		Threshold: threshold,
		PublicKey: publicKey,
		Members:   make([]PublicMember, members),
	}
	secrets := make([]MemberSecret, members)
	for i := uint32(0); i < members; i++ {
		secretBytes, err := privateShares[i].V.MarshalBinary()
		if err != nil {
			return ThresholdCommittee{}, nil, err
		}
		publicBytes, err := publicShares[i].V.MarshalBinary()
		if err != nil {
			return ThresholdCommittee{}, nil, err
		}
		if len(secretBytes) != pointSize || len(publicBytes) != pointSize {
			return ThresholdCommittee{}, nil, errors.New("unexpected threshold share size")
		}
		var privateShare PrivateShare
		var publicShare SharePublicKey
		copy(privateShare[:], secretBytes)
		copy(publicShare[:], publicBytes)
		committee.Members[i] = PublicMember{Index: i, Share: publicShare}
		secrets[i] = MemberSecret{
			CommitteeID: id,
			Epoch:       epoch,
			Index:       i,
			Secret:      privateShare,
			Public:      publicShare,
		}
	}
	if err := validateThresholdCommittee(committee); err != nil {
		return ThresholdCommittee{}, nil, err
	}
	return committee, secrets, nil
}

func validateThresholdCommittee(committee ThresholdCommittee) error {
	if isZeroCommitteeID(committee.ID) {
		return errors.New("committee ID is required")
	}
	if committee.Epoch == 0 {
		return errors.New("committee epoch must be non-zero")
	}
	if len(committee.Members) < minCommitteeMembers || len(committee.Members) > maxCommitteeMembers {
		return errors.New("invalid committee member count")
	}
	if committee.Threshold < 2 || int(committee.Threshold) > len(committee.Members) {
		return errors.New("invalid committee threshold")
	}
	s := newSuite()
	if _, err := publicPoint(s, committee.PublicKey); err != nil {
		return fmt.Errorf("committee public key: %w", err)
	}
	for index, member := range committee.Members {
		if member.Index != uint32(index) {
			return errors.New("committee members must have contiguous ordered indexes")
		}
		if _, err := sharePublicPoint(s, member.Share); err != nil {
			return fmt.Errorf("member %d public share: %w", index, err)
		}
	}
	return nil
}

func isZeroCommitteeID(id CommitteeID) bool {
	return id == CommitteeID{}
}

func sharePublicPoint(s proof.Suite, key SharePublicKey) (kyber.Point, error) {
	p := s.Point()
	if err := p.UnmarshalBinary(key[:]); err != nil {
		return nil, err
	}
	return p, nil
}

func privateShareScalar(s proof.Suite, key PrivateShare) (kyber.Scalar, error) {
	x := s.Scalar()
	if err := x.UnmarshalBinary(key[:]); err != nil {
		return nil, err
	}
	return x, nil
}

func memberForIndex(committee ThresholdCommittee, index uint32) (PublicMember, error) {
	if index >= uint32(len(committee.Members)) {
		return PublicMember{}, errors.New("member index is outside the committee")
	}
	member := committee.Members[index]
	if member.Index != index {
		return PublicMember{}, errors.New("committee member index mismatch")
	}
	return member, nil
}

func CreatePartialDecryption(committee ThresholdCommittee, member MemberSecret, batch *Batch) (*PartialDecryption, error) {
	if err := validateThresholdCommittee(committee); err != nil {
		return nil, err
	}
	if err := validateBatch(batch); err != nil {
		return nil, err
	}
	if member.CommitteeID != committee.ID || member.Epoch != committee.Epoch {
		return nil, errors.New("member secret belongs to a different committee epoch")
	}
	publicMember, err := memberForIndex(committee, member.Index)
	if err != nil {
		return nil, err
	}
	if publicMember.Share != member.Public {
		return nil, errors.New("member public share does not match committee registry")
	}

	s := newSuite()
	secret, err := privateShareScalar(s, member.Secret)
	if err != nil {
		return nil, fmt.Errorf("decode member secret: %w", err)
	}
	publicShare, err := sharePublicPoint(s, member.Public)
	if err != nil {
		return nil, fmt.Errorf("decode member public share: %w", err)
	}
	if !s.Point().Mul(secret, nil).Equal(publicShare) {
		return nil, errors.New("member secret does not match its public share")
	}

	batchDigest, err := batch.Digest()
	if err != nil {
		return nil, err
	}
	partial := &PartialDecryption{
		CommitteeID: committee.ID,
		Epoch:       committee.Epoch,
		MemberIndex: member.Index,
		BatchDigest: batchDigest,
		Points:      make([][pointSize]byte, 0, ChunkCount*batch.Len()),
	}
	points := map[string]kyber.Point{
		"base":          s.Point().Base(),
		"member-public": publicShare,
	}
	predicates := []proof.Predicate{proof.Rep("member-public", "share", "base")}
	pointIndex := 0
	for row := 0; row < ChunkCount; row++ {
		for col := 0; col < batch.Len(); col++ {
			cipherName := fmt.Sprintf("cipher-%d", pointIndex)
			partialName := fmt.Sprintf("partial-%d", pointIndex)
			partialPoint := s.Point().Mul(secret, batch.x[row][col])
			encoded, err := partialPoint.MarshalBinary()
			if err != nil {
				return nil, err
			}
			if len(encoded) != pointSize {
				return nil, errors.New("unexpected partial-decryption point size")
			}
			var stored [pointSize]byte
			copy(stored[:], encoded)
			partial.Points = append(partial.Points, stored)
			points[cipherName] = batch.x[row][col]
			points[partialName] = partialPoint
			predicates = append(predicates, proof.Rep(partialName, "share", cipherName))
			pointIndex++
		}
	}
	predicate := proof.And(predicates...)
	prover := predicate.Prover(s, map[string]kyber.Scalar{"share": secret}, points, nil)
	encodedProof, err := proof.HashProve(s, partialProofDomain(committee, publicMember, batchDigest), prover)
	if err != nil {
		return nil, err
	}
	partial.Proof = encodedProof
	return partial, nil
}

func VerifyPartialDecryption(committee ThresholdCommittee, batch *Batch, partial *PartialDecryption) error {
	if err := validateThresholdCommittee(committee); err != nil {
		return err
	}
	if err := validateBatch(batch); err != nil {
		return err
	}
	if partial == nil {
		return errors.New("partial decryption is required")
	}
	if partial.CommitteeID != committee.ID || partial.Epoch != committee.Epoch {
		return errors.New("partial decryption belongs to a different committee epoch")
	}
	member, err := memberForIndex(committee, partial.MemberIndex)
	if err != nil {
		return err
	}
	batchDigest, err := batch.Digest()
	if err != nil {
		return err
	}
	if partial.BatchDigest != batchDigest {
		return errors.New("partial decryption is bound to a different batch")
	}
	if len(partial.Points) != ChunkCount*batch.Len() {
		return errors.New("partial decryption has the wrong point count")
	}
	if len(partial.Proof) == 0 {
		return errors.New("partial decryption proof is empty")
	}

	s := newSuite()
	publicShare, err := sharePublicPoint(s, member.Share)
	if err != nil {
		return err
	}
	points := map[string]kyber.Point{
		"base":          s.Point().Base(),
		"member-public": publicShare,
	}
	predicates := []proof.Predicate{proof.Rep("member-public", "share", "base")}
	pointIndex := 0
	for row := 0; row < ChunkCount; row++ {
		for col := 0; col < batch.Len(); col++ {
			cipherName := fmt.Sprintf("cipher-%d", pointIndex)
			partialName := fmt.Sprintf("partial-%d", pointIndex)
			partialPoint := s.Point()
			if err := partialPoint.UnmarshalBinary(partial.Points[pointIndex][:]); err != nil {
				return fmt.Errorf("decode partial point %d: %w", pointIndex, err)
			}
			points[cipherName] = batch.x[row][col]
			points[partialName] = partialPoint
			predicates = append(predicates, proof.Rep(partialName, "share", cipherName))
			pointIndex++
		}
	}
	predicate := proof.And(predicates...)
	verifier := predicate.Verifier(s, points)
	if err := proof.HashVerify(s, partialProofDomain(committee, member, batchDigest), verifier, partial.Proof); err != nil {
		return fmt.Errorf("invalid partial-decryption proof: %w", err)
	}
	return nil
}

func ThresholdDecrypt(committee ThresholdCommittee, batch *Batch, partials []*PartialDecryption) ([]PlainCell, error) {
	if err := validateThresholdCommittee(committee); err != nil {
		return nil, err
	}
	if err := validateBatch(batch); err != nil {
		return nil, err
	}
	if len(partials) < int(committee.Threshold) {
		return nil, errors.New("not enough partial decryptions")
	}
	seen := make(map[uint32]struct{}, len(partials))
	decoded := make(map[uint32][]kyber.Point, len(partials))
	s := newSuite()
	for _, partial := range partials {
		if err := VerifyPartialDecryption(committee, batch, partial); err != nil {
			return nil, err
		}
		if _, exists := seen[partial.MemberIndex]; exists {
			return nil, errors.New("duplicate partial-decryption member")
		}
		seen[partial.MemberIndex] = struct{}{}
		points := make([]kyber.Point, len(partial.Points))
		for index := range partial.Points {
			points[index] = s.Point()
			if err := points[index].UnmarshalBinary(partial.Points[index][:]); err != nil {
				return nil, err
			}
		}
		decoded[partial.MemberIndex] = points
	}
	if len(seen) < int(committee.Threshold) {
		return nil, errors.New("not enough unique partial decryptions")
	}

	out := make([]PlainCell, batch.Len())
	for col := 0; col < batch.Len(); col++ {
		for row := 0; row < ChunkCount; row++ {
			pointIndex := row*batch.Len() + col
			publicShares := make([]*share.PubShare, 0, len(decoded))
			for memberIndex, points := range decoded {
				publicShares = append(publicShares, &share.PubShare{I: memberIndex, V: points[pointIndex]})
			}
			sharedPoint, err := share.RecoverCommit(s, publicShares, committee.Threshold, uint32(len(committee.Members)))
			if err != nil {
				return nil, fmt.Errorf("recover shared point for cell %d chunk %d: %w", col, row, err)
			}
			message := s.Point().Sub(batch.y[row][col], sharedPoint)
			data, err := message.Data()
			if err != nil {
				return nil, fmt.Errorf("decrypt cell %d chunk %d: %w", col, row, err)
			}
			if len(data) != ChunkSize {
				return nil, fmt.Errorf("decrypt cell %d chunk %d: got %d bytes", col, row, len(data))
			}
			copy(out[col][row*ChunkSize:], data)
		}
	}
	return out, nil
}

func partialProofDomain(committee ThresholdCommittee, member PublicMember, batchDigest [32]byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-threshold-decryption-context-v1"))
	_, _ = h.Write(committee.ID[:])
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], committee.Epoch)
	_, _ = h.Write(integer[:])
	binary.BigEndian.PutUint32(integer[:4], committee.Threshold)
	_, _ = h.Write(integer[:4])
	_, _ = h.Write(committee.PublicKey[:])
	binary.BigEndian.PutUint32(integer[:4], member.Index)
	_, _ = h.Write(integer[:4])
	_, _ = h.Write(member.Share[:])
	_, _ = h.Write(batchDigest[:])
	return thresholdProofLabel + ":" + hex.EncodeToString(h.Sum(nil))
}
