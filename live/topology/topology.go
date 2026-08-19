// Package topology verifies the public, operator-attested network plan.
// Nothing in this package accepts reader queries or semantic identifiers.
package topology

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"time"
)

const (
	Version          = "nomad-live-topology-v2"
	CellSize         = 1200
	MaximumFileBytes = 1 << 20
)

var operatorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type TrafficClass struct {
	CellSize           uint16 `json:"cell_size"`
	CellIntervalMillis uint32 `json:"cell_interval_ms"`
	MaxLatenessMillis  uint32 `json:"max_lateness_ms"`
	QueueCapacity      uint32 `json:"queue_capacity"`
}

type Operator struct {
	ID              string   `json:"id"`
	Index           uint16   `json:"index"`
	Endpoint        string   `json:"endpoint"`
	PartialEndpoint string   `json:"partial_endpoint"`
	IdentityKey     string   `json:"identity_key"`
	KEXKey          string   `json:"kex_key"`
	PeerPlan        []uint16 `json:"peer_plan"`
	Attestation     string   `json:"attestation"`
}

type Document struct {
	Version   string       `json:"version"`
	NetworkID string       `json:"network_id"`
	Epoch     uint64       `json:"epoch"`
	NotBefore string       `json:"not_before"`
	NotAfter  string       `json:"not_after"`
	Traffic   TrafficClass `json:"traffic"`
	Operators []Operator   `json:"operators"`
}

type Signed struct {
	Document  Document `json:"document"`
	Signature string   `json:"signature"`
}

type Verified struct {
	Document Document
	Digest   [32]byte
}

// ValidateDraft validates public topology structure without requiring
// attestations or an authority signature.
func ValidateDraft(document Document) error {
	return validateDocument(cloneDocument(document), time.Time{})
}

// ValidateAttestations checks that every listed operator signed the same full
// topology draft. It does not add or verify an authority signature.
func ValidateAttestations(document Document) error {
	if err := validateDocument(cloneDocument(document), time.Time{}); err != nil {
		return err
	}
	return verifyAttestations(document)
}

// DraftDigest identifies the exact public proposal that every operator must
// inspect and attest. Collection-order-dependent attestations are excluded.
func DraftDigest(document Document) ([32]byte, error) {
	draft := cloneDocument(document)
	for index := range draft.Operators {
		draft.Operators[index].Attestation = ""
	}
	if err := validateDocument(draft, time.Time{}); err != nil {
		return [32]byte{}, err
	}
	canonical, err := canonicalDocument(draft)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(signingMessage("nomad-topology-draft-v2", canonical)), nil
}

func Load(path string, authority ed25519.PublicKey, now time.Time) (Verified, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Verified{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaximumFileBytes {
		return Verified{}, errors.New("topology must be a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Verified{}, err
	}
	return Verify(data, authority, now)
}

func Verify(encoded []byte, authority ed25519.PublicKey, now time.Time) (Verified, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Verified{}, errors.New("topology encoding is empty or too large")
	}
	if len(authority) != ed25519.PublicKeySize {
		return Verified{}, errors.New("pinned topology authority key is invalid")
	}
	var signed Signed
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return Verified{}, fmt.Errorf("decode topology: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Verified{}, errors.New("trailing topology data")
	}
	if err := validateDocument(signed.Document, now); err != nil {
		return Verified{}, err
	}
	canonical, err := canonicalDocument(signed.Document)
	if err != nil {
		return Verified{}, err
	}
	signature, err := decodeFixed(signed.Signature, ed25519.SignatureSize)
	if err != nil {
		return Verified{}, fmt.Errorf("topology authority signature: %w", err)
	}
	if !ed25519.Verify(authority, signingMessage("nomad-topology-authority-v2", canonical), signature) {
		return Verified{}, errors.New("topology authority signature verification failed")
	}
	if err := verifyAttestations(signed.Document); err != nil {
		return Verified{}, err
	}
	return Verified{Document: signed.Document, Digest: sha256.Sum256(signingMessage("nomad-topology-digest-v2", canonical))}, nil
}

func Sign(document Document, authority ed25519.PrivateKey, identities map[string]ed25519.PrivateKey) (Signed, error) {
	attested := document
	var err error
	for _, operator := range document.Operators {
		attested, err = Attest(attested, operator.ID, identities[operator.ID])
		if err != nil {
			return Signed{}, err
		}
	}
	return Finalize(attested, authority)
}

// Attest signs the complete public topology draft for one operator. All
// attestations are blanked before signing, so independently produced
// signatures bind the same membership, endpoints, keys, validity window,
// traffic class and peer plans without depending on collection order.
func Attest(document Document, operatorID string, identity ed25519.PrivateKey) (Document, error) {
	if len(identity) != ed25519.PrivateKeySize {
		return Document{}, fmt.Errorf("missing identity private key for %s", operatorID)
	}
	copyDocument := cloneDocument(document)
	if err := validateDocument(copyDocument, time.Time{}); err != nil {
		return Document{}, err
	}
	operatorIndex := -1
	for index := range copyDocument.Operators {
		if copyDocument.Operators[index].ID == operatorID {
			operatorIndex = index
			break
		}
	}
	if operatorIndex < 0 {
		return Document{}, fmt.Errorf("operator %q is not in topology", operatorID)
	}
	operator := &copyDocument.Operators[operatorIndex]
	configured, err := decodeFixed(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(configured, identity.Public().(ed25519.PublicKey)) {
		return Document{}, fmt.Errorf("identity private key does not match operator %s", operator.ID)
	}
	message, err := operatorSigningMessage(copyDocument, operator.ID)
	if err != nil {
		return Document{}, err
	}
	operator.Attestation = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, message))
	return copyDocument, nil
}

// Finalize verifies every independently produced operator attestation before
// applying the authority signature. The authority never needs an operator
// identity or key-agreement private key.
func Finalize(document Document, authority ed25519.PrivateKey) (Signed, error) {
	if len(authority) != ed25519.PrivateKeySize {
		return Signed{}, errors.New("topology authority private key is invalid")
	}
	copyDocument := cloneDocument(document)
	if err := validateDocument(copyDocument, time.Time{}); err != nil {
		return Signed{}, err
	}
	if err := verifyAttestations(copyDocument); err != nil {
		return Signed{}, err
	}
	canonical, err := canonicalDocument(copyDocument)
	if err != nil {
		return Signed{}, err
	}
	return Signed{
		Document:  copyDocument,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(authority, signingMessage("nomad-topology-authority-v2", canonical))),
	}, nil
}

func Encode(signed Signed) ([]byte, error) {
	return json.MarshalIndent(signed, "", "  ")
}

func (v Verified) Operator(index uint16) (Operator, error) {
	if int(index) >= len(v.Document.Operators) {
		return Operator{}, errors.New("operator index is outside topology")
	}
	operator := v.Document.Operators[index]
	if operator.Index != index {
		return Operator{}, errors.New("operator index mismatch")
	}
	return operator, nil
}

func (v Verified) OperatorByID(id string) (Operator, error) {
	for _, operator := range v.Document.Operators {
		if operator.ID == id {
			return operator, nil
		}
	}
	return Operator{}, fmt.Errorf("operator %q is not in topology", id)
}

func (v Verified) IncomingPeers(index uint16) []Operator {
	out := make([]Operator, 0)
	for _, operator := range v.Document.Operators {
		for _, peer := range operator.PeerPlan {
			if peer == index {
				out = append(out, operator)
				break
			}
		}
	}
	return out
}

func validateDocument(document Document, now time.Time) error {
	if document.Version != Version {
		return errors.New("unsupported topology version")
	}
	if !operatorIDPattern.MatchString(document.NetworkID) {
		return errors.New("invalid network ID")
	}
	if document.Epoch == 0 {
		return errors.New("topology epoch must be non-zero")
	}
	notBefore, err := time.Parse(time.RFC3339, document.NotBefore)
	if err != nil {
		return errors.New("invalid topology not-before time")
	}
	notAfter, err := time.Parse(time.RFC3339, document.NotAfter)
	if err != nil || !notAfter.After(notBefore) {
		return errors.New("invalid topology not-after time")
	}
	if !now.IsZero() && (now.Before(notBefore) || !now.Before(notAfter)) {
		return errors.New("topology is not currently valid")
	}
	traffic := document.Traffic
	if traffic.CellSize != CellSize {
		return fmt.Errorf("topology cell size must be %d", CellSize)
	}
	if traffic.CellIntervalMillis < 5 || traffic.CellIntervalMillis > 60_000 {
		return errors.New("cell interval is outside the supported public range")
	}
	if traffic.MaxLatenessMillis < traffic.CellIntervalMillis || traffic.MaxLatenessMillis > 10*traffic.CellIntervalMillis {
		return errors.New("maximum lateness must be between one and ten cell intervals")
	}
	if traffic.QueueCapacity < 16 || traffic.QueueCapacity > 65_536 {
		return errors.New("queue capacity is outside the supported public range")
	}
	if len(document.Operators) < 3 || len(document.Operators) > 64 {
		return errors.New("a multi-operator topology requires between three and 64 operators")
	}
	ids := make(map[string]struct{}, len(document.Operators))
	endpoints := make(map[string]struct{}, len(document.Operators))
	partialEndpoints := make(map[string]struct{}, len(document.Operators))
	identityKeys := make(map[string]struct{}, len(document.Operators))
	kexKeys := make(map[string]struct{}, len(document.Operators))
	probeBytes := make([]byte, 32)
	probeBytes[0] = 1
	probePrivate, err := ecdh.X25519().NewPrivateKey(probeBytes)
	if err != nil {
		return errors.New("initialize key-agreement validation")
	}
	for index, operator := range document.Operators {
		if operator.Index != uint16(index) {
			return errors.New("operators must have contiguous ordered indexes")
		}
		if !operatorIDPattern.MatchString(operator.ID) {
			return fmt.Errorf("invalid operator ID %q", operator.ID)
		}
		if _, exists := ids[operator.ID]; exists {
			return fmt.Errorf("duplicate operator ID %q", operator.ID)
		}
		ids[operator.ID] = struct{}{}
		host, port, err := net.SplitHostPort(operator.Endpoint)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("operator %s has invalid UDP endpoint", operator.ID)
		}
		if _, exists := endpoints[operator.Endpoint]; exists {
			return fmt.Errorf("duplicate UDP endpoint %q", operator.Endpoint)
		}
		endpoints[operator.Endpoint] = struct{}{}
		partialURL, err := url.Parse(operator.PartialEndpoint)
		if err != nil || (partialURL.Scheme != "http" && partialURL.Scheme != "https") ||
			partialURL.Hostname() == "" || partialURL.Port() == "" || partialURL.User != nil ||
			(partialURL.Path != "" && partialURL.Path != "/") || partialURL.RawQuery != "" || partialURL.Fragment != "" {
			return fmt.Errorf("operator %s has invalid partial endpoint", operator.ID)
		}
		if _, exists := partialEndpoints[operator.PartialEndpoint]; exists {
			return fmt.Errorf("duplicate partial endpoint %q", operator.PartialEndpoint)
		}
		partialEndpoints[operator.PartialEndpoint] = struct{}{}
		if _, err := decodeFixed(operator.IdentityKey, ed25519.PublicKeySize); err != nil {
			return fmt.Errorf("operator %s has invalid identity key", operator.ID)
		}
		if _, exists := identityKeys[operator.IdentityKey]; exists {
			return fmt.Errorf("duplicate operator identity key for %s", operator.ID)
		}
		identityKeys[operator.IdentityKey] = struct{}{}
		encodedKEX, err := decodeFixed(operator.KEXKey, 32)
		if err != nil {
			return fmt.Errorf("operator %s has invalid key-agreement key", operator.ID)
		}
		publicKEX, err := ecdh.X25519().NewPublicKey(encodedKEX)
		if err != nil {
			return fmt.Errorf("operator %s has invalid key-agreement key", operator.ID)
		}
		if _, err := probePrivate.ECDH(publicKEX); err != nil {
			return fmt.Errorf("operator %s has a non-contributory key-agreement key", operator.ID)
		}
		if _, exists := kexKeys[operator.KEXKey]; exists {
			return fmt.Errorf("duplicate operator key-agreement key for %s", operator.ID)
		}
		kexKeys[operator.KEXKey] = struct{}{}
		if len(operator.PeerPlan) == 0 || len(operator.PeerPlan) >= len(document.Operators) {
			return fmt.Errorf("operator %s has invalid peer plan length", operator.ID)
		}
		peerSlots := make(map[uint16]struct{}, len(operator.PeerPlan))
		for _, peer := range operator.PeerPlan {
			if int(peer) >= len(document.Operators) || peer == operator.Index {
				return fmt.Errorf("operator %s has invalid peer slot %d", operator.ID, peer)
			}
			if _, exists := peerSlots[peer]; exists {
				return fmt.Errorf("operator %s has duplicate peer slot %d", operator.ID, peer)
			}
			peerSlots[peer] = struct{}{}
		}
	}
	return validateStrongConnectivity(document)
}

func validateStrongConnectivity(document Document) error {
	forward := make([][]uint16, len(document.Operators))
	reverse := make([][]uint16, len(document.Operators))
	for _, operator := range document.Operators {
		forward[operator.Index] = append([]uint16(nil), operator.PeerPlan...)
		for _, peer := range operator.PeerPlan {
			reverse[peer] = append(reverse[peer], operator.Index)
		}
	}
	for _, graph := range [][][]uint16{forward, reverse} {
		seen := make([]bool, len(document.Operators))
		stack := []uint16{0}
		for len(stack) > 0 {
			last := len(stack) - 1
			current := stack[last]
			stack = stack[:last]
			if seen[current] {
				continue
			}
			seen[current] = true
			stack = append(stack, graph[current]...)
		}
		for _, reachable := range seen {
			if !reachable {
				return errors.New("operator peer plan must be strongly connected")
			}
		}
	}
	return nil
}

func canonicalDocument(document Document) ([]byte, error) {
	return json.Marshal(cloneDocument(document))
}

func operatorSigningMessage(document Document, operatorID string) ([]byte, error) {
	draft := cloneDocument(document)
	for index := range draft.Operators {
		draft.Operators[index].Attestation = ""
	}
	payload := struct {
		OperatorID string   `json:"operator_id"`
		Document   Document `json:"document"`
	}{operatorID, draft}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return signingMessage("nomad-operator-attestation-v2", encoded), nil
}

func verifyAttestations(document Document) error {
	for _, operator := range document.Operators {
		publicKey, err := decodeFixed(operator.IdentityKey, ed25519.PublicKeySize)
		if err != nil {
			return fmt.Errorf("operator %s identity: %w", operator.ID, err)
		}
		attestation, err := decodeFixed(operator.Attestation, ed25519.SignatureSize)
		if err != nil {
			return fmt.Errorf("operator %s attestation: %w", operator.ID, err)
		}
		message, err := operatorSigningMessage(document, operator.ID)
		if err != nil {
			return err
		}
		if !ed25519.Verify(publicKey, message, attestation) {
			return fmt.Errorf("operator %s attestation verification failed", operator.ID)
		}
	}
	return nil
}

func cloneDocument(document Document) Document {
	copyDocument := document
	copyDocument.Operators = append([]Operator(nil), document.Operators...)
	// Operator order is protocol-significant. Copy peer plans to prevent a
	// caller from mutating a slice while signatures are computed.
	for index := range copyDocument.Operators {
		copyDocument.Operators[index].PeerPlan = append([]uint16(nil), copyDocument.Operators[index].PeerPlan...)
	}
	return copyDocument
}

func signingMessage(domain string, payload []byte) []byte {
	message := make([]byte, 0, len(domain)+len(payload))
	message = append(message, domain...)
	message = append(message, payload...)
	return message
}

func decodeFixed(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid base64 or length")
	}
	return decoded, nil
}

// StableOperatorIDs is used in evidence and bootstrap output. It deliberately
// returns public topology state only.
func (v Verified) StableOperatorIDs() []string {
	ids := make([]string, len(v.Document.Operators))
	for index, operator := range v.Document.Operators {
		ids[index] = operator.ID
	}
	sort.Strings(ids)
	return ids
}
