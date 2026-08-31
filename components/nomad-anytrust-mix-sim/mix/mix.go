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
	// UnmarshalBinary checks that the point is on the curve, not that it is in
	// the prime-order subgroup. Encrypting to the identity yields y = m + r*0 =
	// m, which is the plaintext in cleartext on the wire, and a small-order key
	// leaks it almost as completely.
	//
	// validateThresholdCommittee has rejected this since it was written, but
	// Encrypt never called it, so a caller holding a bare PublicKey that never
	// passed through committee validation -- which is exactly what
	// uplink.Session holds -- had no protection. Checking here covers every
	// encryption entry point at once rather than each remembering separately.
	if err := rejectSmallOrder(s, p); err != nil {
		return nil, fmt.Errorf("encryption public key: %w", err)
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

	// Rows are independent: two scalar multiplications per row per column,
	// nothing shared. The r values stay independent and uniform; only which
	// of them lands where changes, and nothing relies on that.
	parallel(ChunkCount, func(l *lane, row int) {
		b.x[row] = make([]kyber.Point, len(cells))
		b.y[row] = make([]kyber.Point, len(cells))
		h := h.Clone()
		start := row * ChunkSize
		for col := range cells {
			message := l.point().Embed(cells[col][start:start+ChunkSize], l.stream)
			r := l.scalar().Pick(l.stream)
			b.x[row][col] = l.point().Mul(r, nil)
			b.y[row][col] = l.point().Add(message, l.point().Mul(r, h))
		}
	})
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
	return shuffleAndProveWithDomain(pub, in, proofDomain)
}

func shuffleAndProveWithDomain(pub PublicKey, in *Batch, domain string) (*Batch, []byte, error) {
	if err := validateBatch(in); err != nil {
		return nil, nil, err
	}
	if domain == "" {
		return nil, nil, errors.New("shuffle proof domain is required")
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
	encodedProof, err := proof.HashProve(s, domain, prover)
	if err != nil {
		return nil, nil, err
	}
	return out, encodedProof, nil
}

func VerifyShuffle(pub PublicKey, in, out *Batch, encodedProof []byte) error {
	return verifyShuffleWithDomain(pub, in, out, encodedProof, proofDomain)
}

func verifyShuffleWithDomain(pub PublicKey, in, out *Batch, encodedProof []byte, domain string) error {
	if len(encodedProof) == 0 {
		return errors.New("shuffle proof is empty")
	}
	if domain == "" {
		return errors.New("shuffle proof domain is required")
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
	if err := proof.HashVerify(s, domain, verifier, encodedProof); err != nil {
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

// EncryptCell produces the ElGamal ciphertext for one cell, in exactly the
// wire form MarshalWire produces for one column of a batch.
//
// It exists because a publisher encrypts one fragment at a time and Encrypt
// refuses fewer than two cells. That refusal is right for Encrypt: a Batch is
// a mix input, a shuffle of one element is the identity, and a batch of one
// would mix nothing. It is not right for a publisher, which has one fragment
// and needs a ciphertext, not a mix.
//
// The uplink worked around it by encrypting a two-column batch and discarding
// the second column. That is not merely inelegant: the cost of encryption is
// linear in columns, so half of every publisher's per-cell cost was work
// thrown away -- against a 50 ms deployed cell interval it could not meet in
// the first place.
//
// Measured on a 2.1 GHz Xeon, and worth reading in order, because each number
// is the reason for the next:
//
//	103 ms  two-column batch, one column discarded
//	 36 ms  single-cell path, serial
//	 12 ms  single-cell path, rows encrypted in parallel on four cores
//
// The remaining 12 ms is still not mostly ElGamal. Of the 36 ms serial cost,
// about 30 ms is kyber's Point.Embed rejection loop and under 4 ms is the two
// scalar multiplications per row that actually encrypt. Parallelism spreads
// that loop across cores; it does not remove it, and on one core the cost is
// unchanged. Removing it needs a prime-order group encoding, which is a wire
// decision rather than an optimisation. See the seal cost finding in
// nomad-protocol's evidence index.
//
// The result composes: ParseWire assembles individually encrypted cells into
// the batch the committee shuffles and decrypts, which is already how the
// share service reassembles a batch from cached cells. Nothing about the wire
// format changes, so a cell encrypted here is indistinguishable from a column
// of a batch encrypted by Encrypt.
func EncryptCell(pub PublicKey, cell PlainCell) (WireCell, error) {
	return encryptCellWithPadding(pub, cell, rand.Reader)
}

// encryptCellWithPadding takes the padding source so tests can make output
// deterministic. Production always uses crypto/rand.
func encryptCellWithPadding(pub PublicKey, cell PlainCell, padding io.Reader) (WireCell, error) {
	var out WireCell
	if padding == nil {
		return out, errors.New("padding source is required")
	}
	s := newSuite()
	if s.Point().EmbedLen() < ChunkSize {
		return out, errors.New("selected group cannot embed Nomad chunks")
	}
	h, err := publicPoint(s, pub)
	if err != nil {
		return out, err
	}
	// The eighteen rows are independent -- each is its own ElGamal encryption
	// with its own ephemeral -- so they are encrypted in parallel.
	//
	// Most of the cost is not the ElGamal. Measured on a 2.1 GHz Xeon, 30 ms
	// of a 36 ms cell is kyber's Point.Embed, whose rejection loop discards
	// roughly sixteen scalar multiplications per chunk to find a point in the
	// prime-order subgroup; the two multiplications per row are under 4 ms of
	// it. A prime-order encoding would remove that loop rather than spread it.
	//
	// Sealing ahead of time is safe for the emission invariant: the uplink
	// queue is pull-only and a scheduler on a public clock decides when
	// anything leaves, so how long this took never reaches the wire.
	type rowOutput struct {
		encoded [2][]byte
		err     error
	}
	rows := make([]rowOutput, ChunkCount)
	parallel(ChunkCount, func(l *lane, row int) {
		h := h.Clone()
		start := row * ChunkSize
		message := l.point().Embed(cell[start:start+ChunkSize], l.stream)
		r := l.scalar().Pick(l.stream)
		// Same order as MarshalWire: x then y, per row.
		for index, point := range []kyber.Point{
			l.point().Mul(r, nil),
			l.point().Add(message, l.point().Mul(r, h)),
		} {
			encoded, err := point.MarshalBinary()
			if err != nil {
				rows[row].err = err
				return
			}
			if len(encoded) != pointSize {
				rows[row].err = errors.New("unexpected ciphertext point size")
				return
			}
			rows[row].encoded[index] = encoded
		}
	})

	offset := 0
	for row := range rows {
		if rows[row].err != nil {
			return WireCell{}, rows[row].err
		}
		for _, encoded := range rows[row].encoded {
			offset += copy(out[offset:], encoded)
		}
	}
	if offset != cipherSize {
		return WireCell{}, errors.New("internal ciphertext size mismatch")
	}
	if _, err := io.ReadFull(padding, out[offset:]); err != nil {
		return WireCell{}, fmt.Errorf("wire padding: %w", err)
	}
	return out, nil
}
