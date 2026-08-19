package mix

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v4"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
)

// DKGTranscript is a stable commitment to one authenticated DKG ceremony.
// The full signed packet transcript must still be retained by operators; this
// digest is suitable for release evidence and cross-node agreement checks.
type DKGTranscript struct {
	SessionID  [32]byte
	Digest     [32]byte
	Identities []SharePublicKey
	Qualified  []uint32
}

type dkgParticipant struct {
	index    uint32
	identity kyber.Scalar
	public   kyber.Point
	handler  *dkg.DistKeyGenerator
}

// RunAuthenticatedDKG runs Kyber's signed Pedersen DKG state machine for an
// honest in-memory committee. The same deals, responses and signatures are the
// protocol messages that a production transport must broadcast. This function
// removes the trusted dealer from key generation, but it does not provide the
// production network, membership admission or isolated secret storage.
func RunAuthenticatedDKG(id CommitteeID, epoch uint64, members, threshold uint32) (ThresholdCommittee, []MemberSecret, DKGTranscript, error) {
	if isZeroCommitteeID(id) {
		return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("committee ID is required")
	}
	if epoch == 0 {
		return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("committee epoch must be non-zero")
	}
	if members < minCommitteeMembers || members > maxCommitteeMembers {
		return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("invalid DKG member count")
	}
	if threshold < 2 || threshold > members {
		return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("invalid DKG threshold")
	}

	s := newSuite()
	participants := make([]dkgParticipant, members)
	nodes := make([]dkg.Node, members)
	for index := uint32(0); index < members; index++ {
		identity := s.Scalar().Pick(s.RandomStream())
		public := s.Point().Mul(identity, nil)
		participants[index] = dkgParticipant{index: index, identity: identity, public: public}
		nodes[index] = dkg.Node{Index: index, Public: public}
	}
	nonce := dkg.GetNonce()
	if len(nonce) != 32 {
		return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("unexpected DKG nonce size")
	}
	authentication := schnorr.NewScheme(s)
	for index := range participants {
		config := &dkg.Config{
			Suite:     s,
			Longterm:  participants[index].identity,
			NewNodes:  nodes,
			Threshold: threshold,
			FastSync:  true,
			Nonce:     append([]byte(nil), nonce...),
			Auth:      authentication,
		}
		handler, err := dkg.NewDistKeyHandler(config)
		if err != nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, fmt.Errorf("create DKG member %d: %w", index, err)
		}
		participants[index].handler = handler
	}

	deals := make([]*dkg.DealBundle, 0, members)
	for index := range participants {
		bundle, err := participants[index].handler.Deals()
		if err != nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, fmt.Errorf("DKG member %d deals: %w", index, err)
		}
		deals = append(deals, bundle)
	}
	responses := make([]*dkg.ResponseBundle, 0, members)
	for index := range participants {
		bundle, err := participants[index].handler.ProcessDeals(deals)
		if err != nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, fmt.Errorf("DKG member %d process deals: %w", index, err)
		}
		if bundle != nil {
			responses = append(responses, bundle)
		}
	}
	results := make([]*dkg.Result, members)
	for index := range participants {
		result, justification, err := participants[index].handler.ProcessResponses(responses)
		if err != nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, fmt.Errorf("DKG member %d process responses: %w", index, err)
		}
		if justification != nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("honest DKG unexpectedly required justification")
		}
		if result == nil || result.Key == nil || result.Key.Share == nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("DKG did not produce every member share")
		}
		results[index] = result
	}
	for index := 1; index < len(results); index++ {
		if !results[0].PublicEqual(results[index]) {
			return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("DKG members disagree on the public result")
		}
	}

	publicKeyBytes, err := results[0].Key.Public().MarshalBinary()
	if err != nil {
		return ThresholdCommittee{}, nil, DKGTranscript{}, err
	}
	if len(publicKeyBytes) != pointSize {
		return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("unexpected DKG public key size")
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
	byIndex := make(map[uint32]*dkg.Result, members)
	for _, result := range results {
		byIndex[result.Key.Share.I] = result
	}
	for index := uint32(0); index < members; index++ {
		result := byIndex[index]
		if result == nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, fmt.Errorf("missing DKG result for member %d", index)
		}
		secretBytes, err := result.Key.Share.V.MarshalBinary()
		if err != nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, err
		}
		publicSharePoint := s.Point().Mul(result.Key.Share.V, nil)
		publicBytes, err := publicSharePoint.MarshalBinary()
		if err != nil {
			return ThresholdCommittee{}, nil, DKGTranscript{}, err
		}
		if len(secretBytes) != pointSize || len(publicBytes) != pointSize {
			return ThresholdCommittee{}, nil, DKGTranscript{}, errors.New("unexpected DKG share size")
		}
		var privateShare PrivateShare
		var publicShare SharePublicKey
		copy(privateShare[:], secretBytes)
		copy(publicShare[:], publicBytes)
		committee.Members[index] = PublicMember{Index: index, Share: publicShare}
		secrets[index] = MemberSecret{
			CommitteeID: id,
			Epoch:       epoch,
			Index:       index,
			Secret:      privateShare,
			Public:      publicShare,
		}
	}
	if err := validateThresholdCommittee(committee); err != nil {
		return ThresholdCommittee{}, nil, DKGTranscript{}, err
	}
	transcript, err := buildDKGTranscript(nonce, participants, deals, responses, results)
	if err != nil {
		return ThresholdCommittee{}, nil, DKGTranscript{}, err
	}
	return committee, secrets, transcript, nil
}

func buildDKGTranscript(nonce []byte, participants []dkgParticipant, deals []*dkg.DealBundle, responses []*dkg.ResponseBundle, results []*dkg.Result) (DKGTranscript, error) {
	var transcript DKGTranscript
	copy(transcript.SessionID[:], nonce)
	transcript.Identities = make([]SharePublicKey, len(participants))
	for index, participant := range participants {
		encoded, err := participant.public.MarshalBinary()
		if err != nil {
			return DKGTranscript{}, err
		}
		if len(encoded) != pointSize {
			return DKGTranscript{}, errors.New("unexpected DKG identity size")
		}
		copy(transcript.Identities[index][:], encoded)
	}
	transcript.Qualified = make([]uint32, len(results[0].QUAL))
	for index, node := range results[0].QUAL {
		transcript.Qualified[index] = node.Index
	}

	h := sha256.New()
	_, _ = h.Write([]byte("nomad-authenticated-dkg-transcript-v1"))
	_, _ = h.Write(nonce)
	var integer [4]byte
	for _, identity := range transcript.Identities {
		_, _ = h.Write(identity[:])
	}
	for _, bundle := range deals {
		packetHash, err := bundle.Hash()
		if err != nil {
			return DKGTranscript{}, err
		}
		_, _ = h.Write([]byte{1})
		binary.BigEndian.PutUint32(integer[:], bundle.Index())
		_, _ = h.Write(integer[:])
		_, _ = h.Write(packetHash)
		_, _ = h.Write(bundle.Sig())
	}
	for _, bundle := range responses {
		packetHash, err := bundle.Hash()
		if err != nil {
			return DKGTranscript{}, err
		}
		_, _ = h.Write([]byte{2})
		binary.BigEndian.PutUint32(integer[:], bundle.Index())
		_, _ = h.Write(integer[:])
		_, _ = h.Write(packetHash)
		_, _ = h.Write(bundle.Sig())
	}
	for _, qualified := range transcript.Qualified {
		binary.BigEndian.PutUint32(integer[:], qualified)
		_, _ = h.Write(integer[:])
	}
	for _, commitment := range results[0].Key.Commitments() {
		encoded, err := commitment.MarshalBinary()
		if err != nil {
			return DKGTranscript{}, err
		}
		_, _ = h.Write(encoded)
	}
	copy(transcript.Digest[:], h.Sum(nil))
	return transcript, nil
}
