package mix

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/proof"
	kybershuffle "go.dedis.ch/kyber/v4/shuffle"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

const (
	// WireCellSize is the UDP payload size used by the v0.1 test profile.
	WireCellSize = 1200
	// ChunkSize stays below the Ed25519 point embedding limit. Eighteen
	// encrypted chunks occupy 1152 bytes and leave 48 bytes of random padding.
	ChunkSize     = 28
	ChunkCount    = 18
	PlainCellSize = ChunkSize * ChunkCount
	pointSize     = 32
	cipherSize    = ChunkCount * 2 * pointSize
	proofDomain   = "nomad-neff-sequence-shuffle-v1"
)

type PlainCell [PlainCellSize]byte
type WireCell [WireCellSize]byte
type PublicKey [pointSize]byte
type PrivateKey [pointSize]byte

// Batch is a rectangular matrix of ElGamal pairs. Rows are chunks and columns
// are cells. The fields are private so callers cannot accidentally break the
// matrix invariant between proof generation and verification.
type Batch struct {
	x [][]kyber.Point
	y [][]kyber.Point
}

func newSuite() *edwards25519.SuiteEd25519 {
	return edwards25519.NewBlakeSHA256Ed25519()
}

func GenerateKey() (PublicKey, PrivateKey, error) {
	s := newSuite()
	secret := s.Scalar().Pick(s.RandomStream())
	public := s.Point().Mul(secret, nil)
	secretBytes, err := secret.MarshalBinary()
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	if len(secretBytes) != pointSize || len(publicBytes) != pointSize {
		return PublicKey{}, PrivateKey{}, errors.New("unexpected Ed25519 key size")
	}
	var pub PublicKey
	var priv PrivateKey
	copy(pub[:], publicBytes)
	copy(priv[:], secretBytes)
	return pub, priv, nil
}

func publicPoint(s *edwards25519.SuiteEd25519, key PublicKey) (kyber.Point, error) {
	p := s.Point()
	if err := p.UnmarshalBinary(key[:]); err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	return p, nil
}

func privateScalar(s *edwards25519.SuiteEd25519, key PrivateKey) (kyber.Scalar, error) {
	x := s.Scalar()
	if err := x.UnmarshalBinary(key[:]); err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	return x, nil
}

func Encrypt(pub PublicKey, cells []PlainCell) (*Batch, error) {
	if len(cells) < 2 {
		return nil, errors.New("a mix batch requires at least two cells")
	}
	s := newSuite()
	if s.Point().EmbedLen() < ChunkSize {
		return nil, errors.New("selected group cannot embed Nomad chunks")
	}
	h, err := publicPoint(s, pub)
	if err != nil {
		return nil, err
	}
	b := &Batch{x: make([][]kyber.Point, ChunkCount), y: make([][]kyber.Point, ChunkCount)}
	stream := s.RandomStream()
	for row := 0; row < ChunkCount; row++ {
		b.x[row] = make([]kyber.Point, len(cells))
		b.y[row] = make([]kyber.Point, len(cells))
		for col := range cells {
			start := row * ChunkSize
			message := s.Point().Embed(cells[col][start:start+ChunkSize], stream)
			r := s.Scalar().Pick(stream)
			b.x[row][col] = s.Point().Mul(r, nil)
			b.y[row][col] = s.Point().Add(message, s.Point().Mul(r, h))
		}
	}
	return b, nil
}

func (b *Batch) Len() int {
	if b == nil || len(b.x) == 0 {
		return 0
	}
	return len(b.x[0])
}

func validateBatch(b *Batch) error {
	if b == nil || len(b.x) != ChunkCount || len(b.y) != ChunkCount {
		return errors.New("invalid batch dimensions")
	}
	columns := len(b.x[0])
	if columns < 2 {
		return errors.New("a mix batch requires at least two cells")
	}
	for row := 0; row < ChunkCount; row++ {
		if len(b.x[row]) != columns || len(b.y[row]) != columns {
			return errors.New("ragged batch")
		}
		for col := 0; col < columns; col++ {
			if b.x[row][col] == nil || b.y[row][col] == nil {
				return errors.New("nil ciphertext point")
			}
		}
	}
	return nil
}

func (b *Batch) Digest() ([32]byte, error) {
	if err := validateBatch(b); err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-mix-batch-v1"))
	for row := 0; row < ChunkCount; row++ {
		for col := 0; col < b.Len(); col++ {
			for _, p := range []kyber.Point{b.x[row][col], b.y[row][col]} {
				encoded, err := p.MarshalBinary()
				if err != nil {
					return [32]byte{}, err
				}
				_, _ = h.Write(encoded)
			}
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func sequenceChallenges(s *edwards25519.SuiteEd25519, pub PublicKey, in, out *Batch) ([]kyber.Scalar, error) {
	inDigest, err := in.Digest()
	if err != nil {
		return nil, err
	}
	outDigest, err := out.Digest()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-mix-sequence-challenge-v1"))
	_, _ = h.Write(pub[:])
	_, _ = h.Write(inDigest[:])
	_, _ = h.Write(outDigest[:])
	stream := blake2xb.New(h.Sum(nil))
	challenges := make([]kyber.Scalar, ChunkCount)
	for i := range challenges {
		challenges[i] = s.Scalar().Pick(stream)
	}
	return challenges, nil
}

// ShuffleAndProve delegates the cryptographic shuffle to Kyber's implementation
// of Neff's verifiable ElGamal sequence shuffle. Every chunk of a cell follows
// the same secret permutation and receives fresh ElGamal randomness.
func ShuffleAndProve(pub PublicKey, in *Batch) (*Batch, []byte, error) {
	if err := validateBatch(in); err != nil {
		return nil, nil, err
	}
	s := newSuite()
	h, err := publicPoint(s, pub)
	if err != nil {
		return nil, nil, err
	}
	x, y, getProver := kybershuffle.SequencesShuffle(s, nil, h, in.x, in.y, s.RandomStream())
	out := &Batch{x: x, y: y}
	challenges, err := sequenceChallenges(s, pub, in, out)
	if err != nil {
		return nil, nil, err
	}
	prover, err := getProver(challenges)
	if err != nil {
		return nil, nil, err
	}
	encodedProof, err := proof.HashProve(s, proofDomain, prover)
	if err != nil {
		return nil, nil, err
	}
	return out, encodedProof, nil
}

func VerifyShuffle(pub PublicKey, in, out *Batch, encodedProof []byte) error {
	if len(encodedProof) == 0 {
		return errors.New("shuffle proof is empty")
	}
	if err := validateBatch(in); err != nil {
		return fmt.Errorf("input batch: %w", err)
	}
	if err := validateBatch(out); err != nil {
		return fmt.Errorf("output batch: %w", err)
	}
	if in.Len() != out.Len() {
		return errors.New("shuffle changed batch size")
	}
	s := newSuite()
	h, err := publicPoint(s, pub)
	if err != nil {
		return err
	}
	challenges, err := sequenceChallenges(s, pub, in, out)
	if err != nil {
		return err
	}
	xUp, yUp, xDown, yDown := kybershuffle.GetSequenceVerifiable(s, in.x, in.y, out.x, out.y, challenges)
	verifier := kybershuffle.Verifier(s, nil, h, xUp, yUp, xDown, yDown)
	if err := proof.HashVerify(s, proofDomain, verifier, encodedProof); err != nil {
		return fmt.Errorf("invalid shuffle proof: %w", err)
	}
	return nil
}

func Decrypt(priv PrivateKey, batch *Batch) ([]PlainCell, error) {
	if err := validateBatch(batch); err != nil {
		return nil, err
	}
	s := newSuite()
	secret, err := privateScalar(s, priv)
	if err != nil {
		return nil, err
	}
	out := make([]PlainCell, batch.Len())
	for col := 0; col < batch.Len(); col++ {
		for row := 0; row < ChunkCount; row++ {
			shared := s.Point().Mul(secret, batch.x[row][col])
			message := s.Point().Sub(batch.y[row][col], shared)
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

func (b *Batch) MarshalWire() ([]WireCell, error) {
	return b.MarshalWireWithPadding(rand.Reader)
}

func (b *Batch) MarshalWireWithPadding(padding io.Reader) ([]WireCell, error) {
	if err := validateBatch(b); err != nil {
		return nil, err
	}
	if padding == nil {
		return nil, errors.New("padding source is required")
	}
	out := make([]WireCell, b.Len())
	for col := 0; col < b.Len(); col++ {
		offset := 0
		for row := 0; row < ChunkCount; row++ {
			for _, p := range []kyber.Point{b.x[row][col], b.y[row][col]} {
				encoded, err := p.MarshalBinary()
				if err != nil {
					return nil, err
				}
				if len(encoded) != pointSize {
					return nil, errors.New("unexpected ciphertext point size")
				}
				offset += copy(out[col][offset:], encoded)
			}
		}
		if offset != cipherSize {
			return nil, errors.New("internal ciphertext size mismatch")
		}
		if _, err := io.ReadFull(padding, out[col][offset:]); err != nil {
			return nil, fmt.Errorf("wire padding: %w", err)
		}
	}
	return out, nil
}

func ParseWire(cells []WireCell) (*Batch, error) {
	if len(cells) < 2 {
		return nil, errors.New("a mix batch requires at least two wire cells")
	}
	s := newSuite()
	b := &Batch{x: make([][]kyber.Point, ChunkCount), y: make([][]kyber.Point, ChunkCount)}
	for row := 0; row < ChunkCount; row++ {
		b.x[row] = make([]kyber.Point, len(cells))
		b.y[row] = make([]kyber.Point, len(cells))
	}
	for col := range cells {
		offset := 0
		for row := 0; row < ChunkCount; row++ {
			for pair := 0; pair < 2; pair++ {
				p := s.Point()
				if err := p.UnmarshalBinary(cells[col][offset : offset+pointSize]); err != nil {
					return nil, fmt.Errorf("decode cell %d chunk %d: %w", col, row, err)
				}
				if pair == 0 {
					b.x[row][col] = p
				} else {
					b.y[row][col] = p
				}
				offset += pointSize
			}
		}
	}
	return b, validateBatch(b)
}

type Round struct {
	Input  *Batch
	Output *Batch
	Proof  []byte
}

// CommitteeMix applies independently randomized, individually verifiable
// shuffles. Unlinkability needs one honest round; correctness does not require
// trusting a round because every proof is checked before the next round.
func CommitteeMix(pub PublicKey, input *Batch, members int) (*Batch, []Round, error) {
	if members < 1 {
		return nil, nil, errors.New("committee must contain at least one mixer")
	}
	current := input
	rounds := make([]Round, 0, members)
	for i := 0; i < members; i++ {
		output, encodedProof, err := ShuffleAndProve(pub, current)
		if err != nil {
			return nil, nil, fmt.Errorf("mixer %d: %w", i, err)
		}
		if err := VerifyShuffle(pub, current, output, encodedProof); err != nil {
			return nil, nil, fmt.Errorf("mixer %d proof: %w", i, err)
		}
		rounds = append(rounds, Round{Input: current, Output: output, Proof: append([]byte(nil), encodedProof...)})
		current = output
	}
	return current, rounds, nil
}
