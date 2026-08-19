package mix

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
)

// DKGPrivateIdentity and DKGPublicIdentity are dedicated, epoch-scoped
// Pedersen-DKG authentication keys. They must never be reused as Nomad hop,
// publisher, or mixer identity keys.
type DKGPrivateIdentity [pointSize]byte
type DKGPublicIdentity [pointSize]byte

// GenerateDKGIdentity creates an independent Kyber scalar and public point for
// one operator. The private value is suitable for a 0600 operator secret file.
func GenerateDKGIdentity() (DKGPublicIdentity, DKGPrivateIdentity, error) {
	s := newSuite()
	private := s.Scalar().Pick(s.RandomStream())
	public := s.Point().Mul(private, nil)
	privateBytes, err := private.MarshalBinary()
	if err != nil {
		return DKGPublicIdentity{}, DKGPrivateIdentity{}, err
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil {
		return DKGPublicIdentity{}, DKGPrivateIdentity{}, err
	}
	if len(privateBytes) != pointSize || len(publicBytes) != pointSize {
		return DKGPublicIdentity{}, DKGPrivateIdentity{}, errors.New("unexpected DKG identity size")
	}
	var privateIdentity DKGPrivateIdentity
	var publicIdentity DKGPublicIdentity
	copy(privateIdentity[:], privateBytes)
	copy(publicIdentity[:], publicBytes)
	return publicIdentity, privateIdentity, nil
}

// DKGPublicFromPrivate validates a canonical private scalar and derives the
// public point that must be pinned by the operator-attested topology.
func DKGPublicFromPrivate(private DKGPrivateIdentity) (DKGPublicIdentity, error) {
	s := newSuite()
	scalar, err := decodeDKGPrivate(s, private)
	if err != nil {
		return DKGPublicIdentity{}, err
	}
	encoded, err := s.Point().Mul(scalar, nil).MarshalBinary()
	if err != nil {
		return DKGPublicIdentity{}, err
	}
	var public DKGPublicIdentity
	copy(public[:], encoded)
	return public, nil
}

// ValidateDKGPublicIdentity rejects malformed, non-canonical, and identity
// points before they enter a signed committee topology.
func ValidateDKGPublicIdentity(public DKGPublicIdentity) error {
	s := newSuite()
	point := s.Point()
	if err := point.UnmarshalBinary(public[:]); err != nil {
		return fmt.Errorf("decode DKG public identity: %w", err)
	}
	canonical, err := point.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, public[:]) {
		return errors.New("DKG public identity is not canonical")
	}
	if point.Equal(s.Point().Null()) {
		return errors.New("DKG public identity is the identity point")
	}
	// Edwards25519 has cofactor eight. UnmarshalBinary accepts encodings such
	// as the all-zero, low-order point, so canonical encoding alone is not a
	// subgroup check. Clear the cofactor and map back with 8^-1 in the prime
	// order scalar field; equality holds exactly for points in the subgroup
	// used by Kyber's Schnorr authentication scheme.
	eight := s.Scalar().SetInt64(8)
	cleared := s.Point().Mul(eight, point)
	if cleared.Equal(s.Point().Null()) {
		return errors.New("DKG public identity has small order")
	}
	projected := s.Point().Mul(s.Scalar().Inv(eight), cleared)
	if !projected.Equal(point) {
		return errors.New("DKG public identity is outside the prime-order subgroup")
	}
	return nil
}

func decodeDKGPrivate(s dkg.Suite, private DKGPrivateIdentity) (kyber.Scalar, error) {
	scalar := s.Scalar()
	if err := scalar.UnmarshalBinary(private[:]); err != nil {
		return nil, fmt.Errorf("decode DKG private identity: %w", err)
	}
	canonical, err := scalar.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, private[:]) {
		return nil, errors.New("DKG private identity is not canonical")
	}
	if scalar.Equal(s.Scalar().Zero()) {
		return nil, errors.New("DKG private identity is zero")
	}
	return scalar, nil
}

// NewPedersenDKGConfig constructs the official Kyber v4 Pedersen-DKG
// configuration used by the network runner. Packet processing and complaint
// handling remain inside Kyber's Protocol implementation.
func NewPedersenDKGConfig(
	private DKGPrivateIdentity,
	publics []DKGPublicIdentity,
	threshold uint32,
	nonce []byte,
) (*dkg.Config, error) {
	if len(publics) < minCommitteeMembers || len(publics) > maxCommitteeMembers {
		return nil, errors.New("invalid DKG member count")
	}
	if threshold < 2 || int(threshold) > len(publics) {
		return nil, errors.New("invalid DKG threshold")
	}
	if len(nonce) != dkg.NonceLength {
		return nil, errors.New("invalid DKG nonce length")
	}
	s := newSuite()
	secret, err := decodeDKGPrivate(s, private)
	if err != nil {
		return nil, err
	}
	nodes := make([]dkg.Node, len(publics))
	foundOwn := false
	seen := make(map[DKGPublicIdentity]struct{}, len(publics))
	for index, encoded := range publics {
		if err := ValidateDKGPublicIdentity(encoded); err != nil {
			return nil, fmt.Errorf("DKG member %d: %w", index, err)
		}
		if _, exists := seen[encoded]; exists {
			return nil, fmt.Errorf("duplicate DKG public identity at member %d", index)
		}
		seen[encoded] = struct{}{}
		point := s.Point()
		if err := point.UnmarshalBinary(encoded[:]); err != nil {
			return nil, err
		}
		nodes[index] = dkg.Node{Index: uint32(index), Public: point}
		if point.Equal(s.Point().Mul(secret, nil)) {
			foundOwn = true
		}
	}
	if !foundOwn {
		return nil, errors.New("DKG private identity is not in the public membership")
	}
	return &dkg.Config{
		Suite: s, Longterm: secret, NewNodes: nodes, Threshold: threshold,
		FastSync: true, Nonce: append([]byte(nil), nonce...), Auth: schnorr.NewScheme(s),
	}, nil
}

// MaterializePedersenDKG converts one operator's Kyber result into Nomad's
// public committee, that operator's private threshold share, and a stable
// transcript commitment. All packet signatures are reverified here even when
// Kyber's Protocol already verified them at ingress.
func MaterializePedersenDKG(
	id CommitteeID,
	epoch uint64,
	threshold uint32,
	nonce []byte,
	identities []DKGPublicIdentity,
	deals []*dkg.DealBundle,
	responses []*dkg.ResponseBundle,
	justifications []*dkg.JustificationBundle,
	result *dkg.Result,
) (ThresholdCommittee, MemberSecret, DKGTranscript, error) {
	if isZeroCommitteeID(id) || epoch == 0 {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, errors.New("DKG committee context is invalid")
	}
	if result == nil || result.Key == nil || result.Key.Share == nil {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, errors.New("DKG result is incomplete")
	}
	config, err := publicDKGConfig(identities, threshold, nonce)
	if err != nil {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, err
	}
	if err := verifyDKGPackets(config, deals, responses, justifications); err != nil {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, err
	}
	if len(deals) != len(identities) || len(responses) != len(identities) {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, errors.New("DKG transcript is missing a deal or fast-sync response")
	}

	s := newSuite()
	publicKeyBytes, err := result.Key.Public().MarshalBinary()
	if err != nil || len(publicKeyBytes) != pointSize {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, errors.New("invalid DKG public key")
	}
	var publicKey PublicKey
	copy(publicKey[:], publicKeyBytes)
	committee := ThresholdCommittee{
		ID: id, Epoch: epoch, Threshold: threshold, PublicKey: publicKey,
		Members: make([]PublicMember, len(identities)),
	}
	publicPolynomial := share.NewPubPoly(s, s.Point().Base(), result.Key.Commitments())
	for index := range identities {
		encoded, marshalErr := publicPolynomial.Eval(uint32(index)).V.MarshalBinary()
		if marshalErr != nil || len(encoded) != pointSize {
			return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, fmt.Errorf("invalid public DKG share %d", index)
		}
		copy(committee.Members[index].Share[:], encoded)
		committee.Members[index].Index = uint32(index)
	}
	if err := validateThresholdCommittee(committee); err != nil {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, err
	}

	memberIndex := result.Key.Share.I
	if int(memberIndex) >= len(committee.Members) {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, errors.New("DKG private share index is outside committee")
	}
	secretBytes, err := result.Key.Share.V.MarshalBinary()
	if err != nil || len(secretBytes) != pointSize {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, errors.New("invalid DKG private share")
	}
	derivedPublic, err := s.Point().Mul(result.Key.Share.V, nil).MarshalBinary()
	if err != nil || !bytes.Equal(derivedPublic, committee.Members[memberIndex].Share[:]) {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, errors.New("DKG private share does not match public polynomial")
	}
	member := MemberSecret{CommitteeID: id, Epoch: epoch, Index: memberIndex}
	copy(member.Secret[:], secretBytes)
	member.Public = committee.Members[memberIndex].Share

	transcript, err := buildDistributedDKGTranscript(nonce, identities, deals, responses, justifications, result)
	if err != nil {
		return ThresholdCommittee{}, MemberSecret{}, DKGTranscript{}, err
	}
	return committee, member, transcript, nil
}

func publicDKGConfig(publics []DKGPublicIdentity, threshold uint32, nonce []byte) (*dkg.Config, error) {
	if len(publics) < minCommitteeMembers || len(publics) > maxCommitteeMembers || threshold < 2 || int(threshold) > len(publics) || len(nonce) != dkg.NonceLength {
		return nil, errors.New("invalid public DKG configuration")
	}
	s := newSuite()
	nodes := make([]dkg.Node, len(publics))
	seen := make(map[DKGPublicIdentity]struct{}, len(publics))
	for index, encoded := range publics {
		if err := ValidateDKGPublicIdentity(encoded); err != nil {
			return nil, err
		}
		if _, exists := seen[encoded]; exists {
			return nil, errors.New("duplicate DKG public identity")
		}
		seen[encoded] = struct{}{}
		point := s.Point()
		if err := point.UnmarshalBinary(encoded[:]); err != nil {
			return nil, err
		}
		nodes[index] = dkg.Node{Index: uint32(index), Public: point}
	}
	return &dkg.Config{Suite: s, NewNodes: nodes, Threshold: threshold, FastSync: true, Nonce: append([]byte(nil), nonce...), Auth: schnorr.NewScheme(s)}, nil
}

func verifyDKGPackets(config *dkg.Config, deals []*dkg.DealBundle, responses []*dkg.ResponseBundle, justifications []*dkg.JustificationBundle) error {
	seen := make(map[string]struct{})
	for _, group := range []struct {
		phase   string
		packets []dkg.Packet
	}{
		{"deal", dealPackets(deals)},
		{"response", responsePackets(responses)},
		{"justification", justificationPackets(justifications)},
	} {
		for _, packet := range group.packets {
			if packet == nil {
				return fmt.Errorf("nil %s packet", group.phase)
			}
			key := fmt.Sprintf("%s/%d", group.phase, packet.Index())
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate %s packet from member %d", group.phase, packet.Index())
			}
			seen[key] = struct{}{}
			if err := dkg.VerifyPacketSignature(config, packet); err != nil {
				return fmt.Errorf("%s packet %d: %w", group.phase, packet.Index(), err)
			}
		}
	}
	return nil
}

func dealPackets(in []*dkg.DealBundle) []dkg.Packet {
	out := make([]dkg.Packet, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

func responsePackets(in []*dkg.ResponseBundle) []dkg.Packet {
	out := make([]dkg.Packet, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

func justificationPackets(in []*dkg.JustificationBundle) []dkg.Packet {
	out := make([]dkg.Packet, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

func buildDistributedDKGTranscript(
	nonce []byte,
	identities []DKGPublicIdentity,
	deals []*dkg.DealBundle,
	responses []*dkg.ResponseBundle,
	justifications []*dkg.JustificationBundle,
	result *dkg.Result,
) (DKGTranscript, error) {
	var transcript DKGTranscript
	copy(transcript.SessionID[:], nonce)
	transcript.Identities = make([]SharePublicKey, len(identities))
	for index := range identities {
		copy(transcript.Identities[index][:], identities[index][:])
	}
	transcript.Qualified = make([]uint32, len(result.QUAL))
	for index, node := range result.QUAL {
		transcript.Qualified[index] = node.Index
	}
	sort.Slice(transcript.Qualified, func(i, j int) bool { return transcript.Qualified[i] < transcript.Qualified[j] })

	deals = append([]*dkg.DealBundle(nil), deals...)
	responses = append([]*dkg.ResponseBundle(nil), responses...)
	justifications = append([]*dkg.JustificationBundle(nil), justifications...)
	sort.Slice(deals, func(i, j int) bool { return deals[i].Index() < deals[j].Index() })
	sort.Slice(responses, func(i, j int) bool { return responses[i].Index() < responses[j].Index() })
	sort.Slice(justifications, func(i, j int) bool { return justifications[i].Index() < justifications[j].Index() })

	h := sha256.New()
	_, _ = h.Write([]byte("nomad-authenticated-distributed-dkg-transcript-v2"))
	_, _ = h.Write(nonce)
	for _, identity := range identities {
		_, _ = h.Write(identity[:])
	}
	var integer [4]byte
	writePacket := func(kind byte, packet dkg.Packet) error {
		hash, err := packet.Hash()
		if err != nil {
			return err
		}
		_, _ = h.Write([]byte{kind})
		binary.BigEndian.PutUint32(integer[:], packet.Index())
		_, _ = h.Write(integer[:])
		_, _ = h.Write(hash)
		_, _ = h.Write(packet.Sig())
		return nil
	}
	for _, packet := range deals {
		if err := writePacket(1, packet); err != nil {
			return DKGTranscript{}, err
		}
	}
	for _, packet := range responses {
		if err := writePacket(2, packet); err != nil {
			return DKGTranscript{}, err
		}
	}
	for _, packet := range justifications {
		if err := writePacket(3, packet); err != nil {
			return DKGTranscript{}, err
		}
	}
	for _, qualified := range transcript.Qualified {
		binary.BigEndian.PutUint32(integer[:], qualified)
		_, _ = h.Write(integer[:])
	}
	for _, commitment := range result.Key.Commitments() {
		encoded, err := commitment.MarshalBinary()
		if err != nil {
			return DKGTranscript{}, err
		}
		_, _ = h.Write(encoded)
	}
	copy(transcript.Digest[:], h.Sum(nil))
	return transcript, nil
}
