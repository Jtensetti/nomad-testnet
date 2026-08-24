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
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/strictjson"
)

const (
	Version          = "nomad-live-topology-v3"
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

// DKGProfile is public epoch configuration. Its schedule and membership are
// independent of all reader activity and are attested by every operator.
type DKGProfile struct {
	Threshold           uint32 `json:"threshold"`
	SessionID           string `json:"session_id"`
	StartAt             string `json:"start_at"`
	PhaseDurationMillis uint32 `json:"phase_duration_ms"`
}

type Operator struct {
	ID              string   `json:"id"`
	Index           uint16   `json:"index"`
	Endpoint        string   `json:"endpoint"`
	PartialEndpoint string   `json:"partial_endpoint"`
	DKGEndpoint     string   `json:"dkg_endpoint"`
	IdentityKey     string   `json:"identity_key"`
	KEXKey          string   `json:"kex_key"`
	DKGIdentityKey  string   `json:"dkg_identity_key"`
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
	DKG       DKGProfile   `json:"dkg"`
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
	return sha256.Sum256(signingMessage("nomad-topology-draft-v3", canonical)), nil
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
	// Reject a document that more than one parser can read differently before
	// anything is decoded from it. A signature check cannot catch this: each
	// implementation verifies against whatever it parsed, so a duplicate key
	// makes one accept what another refuses.
	if err := strictjson.RejectDuplicateKeys(encoded); err != nil {
		return Verified{}, fmt.Errorf("topology encoding is ambiguous: %w", err)
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
	if !ed25519.Verify(authority, signingMessage("nomad-topology-authority-v3", canonical), signature) {
		return Verified{}, errors.New("topology authority signature verification failed")
	}
	if err := verifyAttestations(signed.Document); err != nil {
		return Verified{}, err
	}
	return Verified{Document: signed.Document, Digest: sha256.Sum256(signingMessage("nomad-topology-digest-v3", canonical))}, nil
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
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(authority, signingMessage("nomad-topology-authority-v3", canonical))),
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
	if document.DKG.Threshold < 2 || int(document.DKG.Threshold) > len(document.Operators) {
		return errors.New("DKG threshold must be between two and the operator count")
	}
	if _, err := decodeFixed(document.DKG.SessionID, 32); err != nil {
		return errors.New("invalid DKG session ID")
	}
	dkgStart, err := time.Parse(time.RFC3339, document.DKG.StartAt)
	if err != nil || dkgStart.Before(notBefore) {
		return errors.New("invalid DKG start time")
	}
	if document.DKG.PhaseDurationMillis < 1_000 || document.DKG.PhaseDurationMillis > 600_000 {
		return errors.New("DKG phase duration must be between one second and ten minutes")
	}
	dkgEnd := dkgStart.Add(4 * time.Duration(document.DKG.PhaseDurationMillis) * time.Millisecond)
	if dkgEnd.After(notAfter) {
		return errors.New("DKG schedule exceeds topology validity")
	}
	ids := make(map[string]struct{}, len(document.Operators))
	endpoints := make(map[string]struct{}, len(document.Operators))
	partialEndpoints := make(map[string]struct{}, len(document.Operators))
	dkgEndpoints := make(map[string]struct{}, len(document.Operators))
	identityKeys := make(map[string]struct{}, len(document.Operators))
	kexKeys := make(map[string]struct{}, len(document.Operators))
	dkgIdentityKeys := make(map[string]struct{}, len(document.Operators))
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
		canonical, err := canonicalEndpoint(operator.Endpoint)
		if err != nil {
			return fmt.Errorf("operator %s has invalid UDP endpoint: %w", operator.ID, err)
		}
		if _, exists := endpoints[canonical]; exists {
			return fmt.Errorf("duplicate UDP endpoint %q", operator.Endpoint)
		}
		endpoints[canonical] = struct{}{}
		partialURL, err := url.Parse(operator.PartialEndpoint)
		if err != nil || (partialURL.Scheme != "http" && partialURL.Scheme != "https") ||
			partialURL.Hostname() == "" || partialURL.Port() == "" || partialURL.User != nil ||
			(partialURL.Path != "" && partialURL.Path != "/") || partialURL.RawQuery != "" || partialURL.Fragment != "" {
			return fmt.Errorf("operator %s has invalid partial endpoint", operator.ID)
		}
		canonicalPartial, err := canonicalURLEndpoint(partialURL)
		if err != nil {
			return fmt.Errorf("operator %s has invalid partial endpoint: %w", operator.ID, err)
		}
		if _, exists := partialEndpoints[canonicalPartial]; exists {
			return fmt.Errorf("duplicate partial endpoint %q", operator.PartialEndpoint)
		}
		partialEndpoints[canonicalPartial] = struct{}{}
		dkgURL, err := url.Parse(operator.DKGEndpoint)
		if err != nil || !validCeremonyURL(dkgURL) {
			return fmt.Errorf("operator %s has invalid DKG endpoint", operator.ID)
		}
		canonicalDKG, err := canonicalURLEndpoint(dkgURL)
		if err != nil {
			return fmt.Errorf("operator %s has invalid DKG endpoint: %w", operator.ID, err)
		}
		if _, exists := dkgEndpoints[canonicalDKG]; exists {
			return fmt.Errorf("duplicate DKG endpoint %q", operator.DKGEndpoint)
		}
		dkgEndpoints[canonicalDKG] = struct{}{}
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
		dkgIdentityBytes, err := decodeFixed(operator.DKGIdentityKey, len(mix.DKGPublicIdentity{}))
		if err != nil {
			return fmt.Errorf("operator %s has invalid DKG identity key", operator.ID)
		}
		var dkgIdentity mix.DKGPublicIdentity
		copy(dkgIdentity[:], dkgIdentityBytes)
		if err := mix.ValidateDKGPublicIdentity(dkgIdentity); err != nil {
			return fmt.Errorf("operator %s has invalid DKG identity key: %w", operator.ID, err)
		}
		if _, exists := dkgIdentityKeys[operator.DKGIdentityKey]; exists {
			return fmt.Errorf("duplicate operator DKG identity key for %s", operator.ID)
		}
		dkgIdentityKeys[operator.DKGIdentityKey] = struct{}{}
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

func validCeremonyURL(endpoint *url.URL) bool {
	if endpoint == nil || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return false
	}
	if endpoint.Scheme == "https" {
		return true
	}
	if endpoint.Scheme != "http" {
		return false
	}
	host := endpoint.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	return signingMessage("nomad-operator-attestation-v3", encoded), nil
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

// OperatorIdentity decodes an operator's signing key from the signed topology.
// Callers that verify or accuse an operator must resolve its key this way
// rather than carrying one alongside, so the key they act on is always the one
// the topology signature covers.
func OperatorIdentity(operator Operator) (ed25519.PublicKey, error) {
	decoded, err := decodeFixed(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.New("invalid operator identity key")
	}
	return ed25519.PublicKey(decoded), nil
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

// canonicalEndpoint reduces an operator's UDP endpoint to one form per socket
// address, so the distinctness check compares what endpoints mean rather than
// how they are spelled.
//
// What this enforces, precisely: **one canonical form per socket address**, and
// loopback folded to a single host. It does not establish that two operators
// are two machines, and still less two trust domains -- 198.51.100.7:4200 and
// 198.51.100.7:4201 are two socket addresses on one host and are admitted as
// two operators, as this package's own fixtures rely on. An independence claim
// needs more than this function can supply from a document.
//
// What it does close is spelling. One address has many: [::1] and
// [0:0:0:0:0:0:0:1], 2001:db8::1 with and without zero padding, 127.0.0.1 and
// its IPv4-mapped form [::ffff:127.0.0.1], operator-a and operator-a. (the
// trailing dot is the root label, so they are one name), OPERATOR-A and
// operator-a, and localhost against a loopback literal. Every one of those was
// admitted as two distinct operators before this function existed.
//
// It parses rather than resolves. netip.ParseAddr never touches DNS, which
// matters twice over: a signed document's validity must not depend on what a
// resolver says at the moment someone checks it, and admission must not perform
// a network lookup.
//
// The host grammar is strict on purpose. An unparseable address used to fall
// through to "treat it as a hostname", which admitted operator-a\x00,
// "operator-a " with a space, [foo:bar], 2130706433 and 0177.0.0.1 -- each of
// which some other implementation reads as a different host than Go does. That
// is the same cross-parser divergence strictjson.RejectDuplicateKeys exists to
// refuse for JSON, and the reasoning is identical: a document one implementation
// admits as N operators and another as N-1 is a document that has not been
// agreed on. There is no silent fallback: a bracketed host that is not an
// address is refused rather than reinterpreted.
//
// The residual gaps, stated rather than left to be discovered: two different
// hostnames pointing at one machine are indistinguishable here, because that is
// a fact about DNS and not about the document; and nothing here knows whether
// two addresses belong to one operator.
func canonicalEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	if host == "" || port == "" {
		return "", errors.New("endpoint needs both a host and a port")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("invalid port %q", port)
	}
	if number == 0 {
		// Port zero means "any port" to the operating system, so it names
		// nothing a peer can send to. Admitting it defers the failure to the
		// first node that tries to use the document.
		return "", errors.New("port must not be zero")
	}

	canonicalHost, err := canonicalHost(host, strings.HasPrefix(endpoint, "["))
	if err != nil {
		return "", err
	}
	return canonicalHost + ":" + strconv.FormatUint(number, 10), nil
}

// loopbackHost is the single key every loopback spelling folds onto:
// 127.0.0.0/8, ::1, and the name localhost, which RFC 6761 reserves and
// requires to resolve to loopback. validCeremonyURL already relies on that, and
// two operators on one machine's loopback are not two operators however they
// are written.
const loopbackHost = "loopback"

func canonicalHost(host string, bracketed bool) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if address.Zone() != "" {
			// A zone distinguishes interfaces, but live/node keys inbound
			// peers on IP and port with the zone dropped, so two zone-distinct
			// peers are indistinguishable as datagram sources at runtime.
			// Admitting one would promise a distinctness the node does not
			// deliver, so it is refused rather than silently flattened.
			return "", errors.New("a zoned address cannot be distinguished at runtime")
		}
		if !usableAsPeerAddress(address) {
			// Same rationale as port zero: these name nothing a peer can send
			// to, and "0.0.0.0" is the natural typo when a listen flag is
			// copied into an endpoint field.
			return "", fmt.Errorf("address %s cannot be a peer endpoint", address)
		}
		if address.IsLoopback() {
			return loopbackHost, nil
		}
		return address.String(), nil
	}
	if bracketed {
		return "", errors.New("a bracketed host must be an IP address")
	}
	return canonicalHostname(host)
}

func usableAsPeerAddress(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	// The IPv4 limited broadcast address has no netip predicate of its own.
	return address != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// canonicalHostname folds a DNS name to one spelling and refuses anything that
// is not one.
//
// The grammar is the letter-digit-hyphen form, which is what a UDP endpoint in
// a signed document can honestly carry: ASCII only, so folding is ASCII-only
// too. strings.ToLower is Unicode-aware and maps U+212A KELVIN SIGN onto "k",
// which would merge two byte-distinct hosts and reject a legitimate topology --
// the one false-merge direction that existed here.
func canonicalHostname(host string) (string, error) {
	// Exactly one trailing dot is the root label: operator-a. is operator-a.
	name := strings.TrimSuffix(host, ".")
	if name == "" || strings.HasSuffix(name, ".") {
		return "", errors.New("host is empty or has a trailing empty label")
	}
	if len(name) > 253 {
		return "", errors.New("host is longer than a DNS name may be")
	}
	lowered := make([]byte, 0, len(name))
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("host label %q is empty or too long", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("host label %q begins or ends with a hyphen", label)
		}
		if len(lowered) > 0 {
			lowered = append(lowered, '.')
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			switch {
			case character >= 'a' && character <= 'z',
				character >= '0' && character <= '9',
				character == '-':
				lowered = append(lowered, character)
			case character >= 'A' && character <= 'Z':
				lowered = append(lowered, character+('a'-'A'))
			default:
				return "", fmt.Errorf("host label %q contains a character that is not "+
					"a letter, digit or hyphen", label)
			}
		}
	}
	// RFC 1123 2.1: the top-level label must not be all-numeric. The rule
	// exists precisely so a hostname cannot be read as a dotted quad, and
	// without it "2130706433" and "0177.0.0.1" pass as hostnames here while
	// inet_aton reads both as 127.0.0.1.
	labels := strings.Split(string(lowered), ".")
	if allDigits(labels[len(labels)-1]) {
		return "", errors.New("the top-level host label is all digits, so this is " +
			"neither a hostname nor an address this parser accepts")
	}
	if string(lowered) == "localhost" {
		return loopbackHost, nil
	}
	return string(lowered), nil
}

func allDigits(label string) bool {
	if label == "" {
		return false
	}
	for index := 0; index < len(label); index++ {
		if label[index] < '0' || label[index] > '9' {
			return false
		}
	}
	return true
}

// canonicalURLEndpoint reduces an operator's HTTP endpoint to one form per
// socket address, exactly as canonicalEndpoint does for the UDP one.
//
// The same weakness applied and for the same reason: the distinctness check
// compared raw strings, so "http://127.0.0.1:4300" and "http://127.0.0.1:4300/"
// were two operators, as were a host in two cases and a scheme in two cases.
//
// The scheme is deliberately **not** part of the key. http://operator-a:4300
// and https://operator-a:4300 are one host on one TCP port; keying on the
// scheme would let two operators occupy that port by differing only in a field
// that says how to talk to it rather than where it is. The scheme is still
// validated by the caller, which is where it belongs. The path is likewise not
// part of the key: the caller already constrains it to "" or "/", which are the
// same resource and were the two spellings that compared unequal.
func canonicalURLEndpoint(endpoint *url.URL) (string, error) {
	// These guards are defence in depth. Every caller validates the URL first,
	// so they are unreachable today; they are kept so this function is safe if
	// somebody later calls it somewhere else.
	if endpoint == nil {
		return "", errors.New("endpoint is required")
	}
	host := endpoint.Hostname()
	port := endpoint.Port()
	if host == "" || port == "" {
		return "", errors.New("endpoint needs both a host and a port")
	}
	return canonicalEndpoint(net.JoinHostPort(host, port))
}
