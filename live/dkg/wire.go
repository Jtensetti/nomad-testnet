package dkgnet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

const (
	WireVersion       = 1
	MaximumPacketSize = 256 << 10
)

type Phase string

const (
	DealPhase          Phase = "deal"
	ResponsePhase      Phase = "response"
	JustificationPhase Phase = "justification"
	ResultPhase        Phase = "result"
)

type dealWire struct {
	Version      int        `json:"version"`
	DealerIndex  uint32     `json:"dealer_index"`
	Deals        []dealItem `json:"deals"`
	Public       []string   `json:"public"`
	SessionID    string     `json:"session_id"`
	Signature    string     `json:"signature"`
}

type dealItem struct {
	ShareIndex     uint32 `json:"share_index"`
	EncryptedShare string `json:"encrypted_share"`
}

type responseWire struct {
	Version    int            `json:"version"`
	ShareIndex uint32         `json:"share_index"`
	Responses  []responseItem `json:"responses"`
	SessionID  string         `json:"session_id"`
	Signature  string         `json:"signature"`
}

type responseItem struct {
	DealerIndex uint32 `json:"dealer_index"`
	Status      int32  `json:"status"`
}

type justificationWire struct {
	Version        int                 `json:"version"`
	DealerIndex    uint32              `json:"dealer_index"`
	Justifications []justificationItem `json:"justifications"`
	SessionID      string              `json:"session_id"`
	Signature      string              `json:"signature"`
}

type justificationItem struct {
	ShareIndex uint32 `json:"share_index"`
	Share      string `json:"share"`
}

func EncodePacket(packet dkg.Packet) (Phase, uint32, []byte, error) {
	if packet == nil {
		return "", 0, nil, errors.New("DKG packet is required")
	}
	switch value := packet.(type) {
	case *dkg.DealBundle:
		sort.Slice(value.Deals, func(i, j int) bool { return value.Deals[i].ShareIndex < value.Deals[j].ShareIndex })
		wire := dealWire{Version: WireVersion, DealerIndex: value.DealerIndex, Deals: make([]dealItem, len(value.Deals)), Public: make([]string, len(value.Public)), SessionID: base64.StdEncoding.EncodeToString(value.SessionID), Signature: base64.StdEncoding.EncodeToString(value.Signature)}
		for index, deal := range value.Deals {
			wire.Deals[index] = dealItem{ShareIndex: deal.ShareIndex, EncryptedShare: base64.StdEncoding.EncodeToString(deal.EncryptedShare)}
		}
		for index, point := range value.Public {
			encoded, err := point.MarshalBinary()
			if err != nil {
				return "", 0, nil, err
			}
			wire.Public[index] = base64.StdEncoding.EncodeToString(encoded)
		}
		encoded, err := json.Marshal(wire)
		return DealPhase, value.DealerIndex, encoded, err
	case *dkg.ResponseBundle:
		sort.Slice(value.Responses, func(i, j int) bool { return value.Responses[i].DealerIndex < value.Responses[j].DealerIndex })
		wire := responseWire{Version: WireVersion, ShareIndex: value.ShareIndex, Responses: make([]responseItem, len(value.Responses)), SessionID: base64.StdEncoding.EncodeToString(value.SessionID), Signature: base64.StdEncoding.EncodeToString(value.Signature)}
		for index, response := range value.Responses {
			wire.Responses[index] = responseItem{DealerIndex: response.DealerIndex, Status: int32(response.Status)}
		}
		encoded, err := json.Marshal(wire)
		return ResponsePhase, value.ShareIndex, encoded, err
	case *dkg.JustificationBundle:
		sort.Slice(value.Justifications, func(i, j int) bool { return value.Justifications[i].ShareIndex < value.Justifications[j].ShareIndex })
		wire := justificationWire{Version: WireVersion, DealerIndex: value.DealerIndex, Justifications: make([]justificationItem, len(value.Justifications)), SessionID: base64.StdEncoding.EncodeToString(value.SessionID), Signature: base64.StdEncoding.EncodeToString(value.Signature)}
		for index, justification := range value.Justifications {
			encoded, err := justification.Share.MarshalBinary()
			if err != nil {
				return "", 0, nil, err
			}
			wire.Justifications[index] = justificationItem{ShareIndex: justification.ShareIndex, Share: base64.StdEncoding.EncodeToString(encoded)}
		}
		encoded, err := json.Marshal(wire)
		return JustificationPhase, value.DealerIndex, encoded, err
	default:
		return "", 0, nil, errors.New("unsupported DKG packet type")
	}
}

func DecodePacket(phase Phase, encoded []byte) (dkg.Packet, error) {
	if len(encoded) == 0 || len(encoded) > MaximumPacketSize {
		return nil, errors.New("DKG packet is empty or too large")
	}
	switch phase {
	case DealPhase:
		var wire dealWire
		if err := strictJSON(encoded, &wire); err != nil {
			return nil, err
		}
		if wire.Version != WireVersion || len(wire.Deals) < 2 || len(wire.Deals) > 64 || len(wire.Public) < 2 || len(wire.Public) > 64 {
			return nil, errors.New("invalid DKG deal dimensions")
		}
		return decodeDealWire(wire, encoded)
	case ResponsePhase:
		var wire responseWire
		if err := strictJSON(encoded, &wire); err != nil {
			return nil, err
		}
		return decodeResponseWire(wire, encoded)
	case JustificationPhase:
		var wire justificationWire
		if err := strictJSON(encoded, &wire); err != nil {
			return nil, err
		}
		return decodeJustificationWire(wire, encoded)
	default:
		return nil, errors.New("unsupported DKG packet phase")
	}
}

func decodeDealWire(wire dealWire, original []byte) (dkg.Packet, error) {
	if wire.Version != WireVersion || len(wire.Deals) < 2 || len(wire.Deals) > 64 || len(wire.Public) < 2 || len(wire.Public) > 64 {
		return nil, errors.New("invalid DKG deal dimensions")
	}
	session, err := decodeBase64(wire.SessionID, 32)
	if err != nil {
		return nil, errors.New("invalid DKG deal session")
	}
	signature, err := decodeVariable(wire.Signature, 1, 128)
	if err != nil {
		return nil, errors.New("invalid DKG deal signature")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	actual := &dkg.DealBundle{DealerIndex: wire.DealerIndex, Deals: make([]dkg.Deal, len(wire.Deals)), SessionID: session, Signature: signature}
	actual.Public = make([]kyber.Point, len(wire.Public))
	for index, encoded := range wire.Public {
		pointBytes, err := decodeBase64(encoded, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid DKG public coefficient %d", index)
		}
		point := suite.Point()
		if err := point.UnmarshalBinary(pointBytes); err != nil {
			return nil, fmt.Errorf("invalid DKG public coefficient %d", index)
		}
		actual.Public[index] = point
	}
	seen := make(map[uint32]struct{}, len(wire.Deals))
	for index, item := range wire.Deals {
		if _, exists := seen[item.ShareIndex]; exists {
			return nil, errors.New("duplicate DKG deal share index")
		}
		seen[item.ShareIndex] = struct{}{}
		ciphertext, err := decodeVariable(item.EncryptedShare, 1, 512)
		if err != nil {
			return nil, fmt.Errorf("invalid encrypted DKG share %d", index)
		}
		actual.Deals[index] = dkg.Deal{ShareIndex: item.ShareIndex, EncryptedShare: ciphertext}
	}
	return requireCanonical(actual, original)
}

func decodeResponseWire(wire responseWire, original []byte) (dkg.Packet, error) {
	if wire.Version != WireVersion || len(wire.Responses) < 2 || len(wire.Responses) > 64 {
		return nil, errors.New("invalid DKG response dimensions")
	}
	session, err := decodeBase64(wire.SessionID, 32)
	if err != nil {
		return nil, errors.New("invalid DKG response session")
	}
	signature, err := decodeVariable(wire.Signature, 1, 128)
	if err != nil {
		return nil, errors.New("invalid DKG response signature")
	}
	bundle := &dkg.ResponseBundle{ShareIndex: wire.ShareIndex, Responses: make([]dkg.Response, len(wire.Responses)), SessionID: session, Signature: signature}
	seen := make(map[uint32]struct{}, len(wire.Responses))
	for index, item := range wire.Responses {
		if _, exists := seen[item.DealerIndex]; exists || (item.Status != int32(dkg.Success) && item.Status != int32(dkg.Complaint)) {
			return nil, errors.New("invalid or duplicate DKG response")
		}
		seen[item.DealerIndex] = struct{}{}
		bundle.Responses[index] = dkg.Response{DealerIndex: item.DealerIndex, Status: dkg.Status(item.Status)}
	}
	return requireCanonical(bundle, original)
}

func decodeJustificationWire(wire justificationWire, original []byte) (dkg.Packet, error) {
	if wire.Version != WireVersion || len(wire.Justifications) == 0 || len(wire.Justifications) > 64 {
		return nil, errors.New("invalid DKG justification dimensions")
	}
	session, err := decodeBase64(wire.SessionID, 32)
	if err != nil {
		return nil, errors.New("invalid DKG justification session")
	}
	signature, err := decodeVariable(wire.Signature, 1, 128)
	if err != nil {
		return nil, errors.New("invalid DKG justification signature")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	bundle := &dkg.JustificationBundle{DealerIndex: wire.DealerIndex, Justifications: make([]dkg.Justification, len(wire.Justifications)), SessionID: session, Signature: signature}
	seen := make(map[uint32]struct{}, len(wire.Justifications))
	for index, item := range wire.Justifications {
		if _, exists := seen[item.ShareIndex]; exists {
			return nil, errors.New("duplicate DKG justification share index")
		}
		seen[item.ShareIndex] = struct{}{}
		shareBytes, err := decodeBase64(item.Share, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid DKG justification %d", index)
		}
		share := suite.Scalar()
		if err := share.UnmarshalBinary(shareBytes); err != nil {
			return nil, fmt.Errorf("invalid DKG justification %d", index)
		}
		bundle.Justifications[index] = dkg.Justification{ShareIndex: item.ShareIndex, Share: share}
	}
	return requireCanonical(bundle, original)
}

func requireCanonical(packet dkg.Packet, original []byte) (dkg.Packet, error) {
	_, _, canonical, err := EncodePacket(packet)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, original) {
		return nil, errors.New("DKG packet encoding is not canonical")
	}
	return packet, nil
}

func strictJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing DKG packet data")
	}
	return nil
}

func decodeBase64(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid base64 or length")
	}
	return decoded, nil
}

func decodeVariable(encoded string, minimum, maximum int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum {
		return nil, errors.New("invalid base64 or length")
	}
	return decoded, nil
}
