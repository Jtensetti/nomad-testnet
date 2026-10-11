package rlnc

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	PacketSize       = 504
	PacketHeaderSize = 28
)

var packetMagic = [4]byte{'N', 'R', 'L', 1}

type GenerationID [16]byte

// Packet is the fixed-size cleartext unit carried inside an encrypted Nomad
// mix cell. Its generation metadata is public object-routing information, not
// authentication; reconstructed bytes still require commitment and signature
// verification.
type Packet struct {
	Generation   GenerationID
	K            int
	SymbolSize   int
	OriginalSize int
	Symbol       Symbol
}

func NewPacket(generation GenerationID, k, symbolSize, originalSize int, symbol Symbol) (Packet, error) {
	p := Packet{
		Generation:   generation,
		K:            k,
		SymbolSize:   symbolSize,
		OriginalSize: originalSize,
		Symbol:       symbol,
	}
	if err := p.validate(); err != nil {
		return Packet{}, err
	}
	return p, nil
}

func (p Packet) MarshalBinary() ([]byte, error) {
	return p.MarshalBinaryFrom(rand.Reader)
}

func (p Packet) MarshalBinaryFrom(random io.Reader) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if random == nil {
		return nil, errors.New("nil padding source")
	}
	out := make([]byte, PacketSize)
	copy(out[0:4], packetMagic[:])
	copy(out[4:20], p.Generation[:])
	binary.BigEndian.PutUint16(out[20:22], uint16(p.K))
	binary.BigEndian.PutUint16(out[22:24], uint16(p.SymbolSize))
	binary.BigEndian.PutUint32(out[24:28], uint32(p.OriginalSize))
	copy(out[28:28+p.K], p.Symbol.Coeff)
	end := 28 + p.K + p.SymbolSize
	copy(out[28+p.K:end], p.Symbol.Data)
	if _, err := io.ReadFull(random, out[end:]); err != nil {
		return nil, fmt.Errorf("random packet padding: %w", err)
	}
	return out, nil
}

func ParsePacket(wire []byte) (Packet, error) {
	if len(wire) != PacketSize {
		return Packet{}, fmt.Errorf("packet must be exactly %d bytes", PacketSize)
	}
	if string(wire[0:4]) != string(packetMagic[:]) {
		return Packet{}, errors.New("unsupported packet magic or version")
	}
	var generation GenerationID
	copy(generation[:], wire[4:20])
	k := int(binary.BigEndian.Uint16(wire[20:22]))
	symbolSize := int(binary.BigEndian.Uint16(wire[22:24]))
	originalSize := int(binary.BigEndian.Uint32(wire[24:28]))
	if PacketHeaderSize+k+symbolSize > len(wire) {
		return Packet{}, errors.New("packet dimensions exceed fixed cell")
	}
	p, err := NewPacket(generation, k, symbolSize, originalSize, Symbol{
		Coeff: append([]byte(nil), wire[28:28+k]...),
		Data:  append([]byte(nil), wire[28+k:28+k+symbolSize]...),
	})
	if err != nil {
		return Packet{}, err
	}
	return p, nil
}

func ReEncodePackets(packets []Packet) (Packet, error) {
	if len(packets) == 0 {
		return Packet{}, errors.New("no packets")
	}
	first := packets[0]
	symbols := make([]Symbol, len(packets))
	for i, packet := range packets {
		if packet.Generation != first.Generation || packet.K != first.K ||
			packet.SymbolSize != first.SymbolSize || packet.OriginalSize != first.OriginalSize {
			return Packet{}, errors.New("packets belong to incompatible generations")
		}
		if err := packet.validate(); err != nil {
			return Packet{}, err
		}
		symbols[i] = packet.Symbol
	}
	symbol, err := ReEncode(symbols)
	if err != nil {
		return Packet{}, err
	}
	return NewPacket(first.Generation, first.K, first.SymbolSize, first.OriginalSize, symbol)
}

func (p Packet) validate() error {
	if p.K <= 0 || p.SymbolSize <= 0 || p.OriginalSize <= 0 {
		return errors.New("invalid packet dimensions")
	}
	if p.K > int(^uint16(0)) || p.SymbolSize > int(^uint16(0)) ||
		uint64(p.OriginalSize) > uint64(^uint32(0)) {
		return errors.New("packet dimensions exceed wire fields")
	}
	if PacketHeaderSize+p.K+p.SymbolSize > PacketSize {
		return errors.New("coded symbol does not fit fixed packet")
	}
	capacity := uint64(p.K) * uint64(p.SymbolSize)
	if uint64(p.OriginalSize) > capacity {
		return errors.New("original size exceeds generation capacity")
	}
	if len(p.Symbol.Coeff) != p.K || len(p.Symbol.Data) != p.SymbolSize {
		return errors.New("symbol dimensions do not match packet")
	}
	if !anyNonZero(p.Symbol.Coeff) {
		return errors.New("zero coefficient vector")
	}
	return nil
}
