package dkgnet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

var ErrEquivocation = errors.New("DKG sender equivocation")

type messageKey struct {
	Phase  Phase
	Sender uint32
}

type storedMessage struct {
	Envelope Envelope
	Payload  []byte
	Encoded  []byte
	Digest   [32]byte
}

// Store is an append-only ceremony journal. An interrupted session cannot be
// resumed because Kyber's ephemeral dealer polynomial is intentionally not
// serialized; the operator must attest a fresh topology/session instead.
type Store struct {
	root      string
	network   topology.Verified
	mu        sync.Mutex
	messages  map[messageKey]storedMessage
	fatal     chan error
	fatalOnce sync.Once
}

func NewStore(root string, network topology.Verified) (*Store, error) {
	if root == "" {
		return nil, errors.New("DKG state directory is required")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("DKG state path must be a real directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		return nil, errors.New("DKG state directory is not empty; start a fresh signed session after interruption")
	}
	if err := os.Mkdir(filepath.Join(root, "messages"), 0o700); err != nil {
		return nil, err
	}
	marker := []byte(fmt.Sprintf("network=%s\nepoch=%d\ntopology=%x\nsession=%s\n", network.Document.NetworkID, network.Document.Epoch, network.Digest, network.Document.DKG.SessionID))
	if err := writeNew(filepath.Join(root, "RUNNING"), marker, 0o600); err != nil {
		return nil, err
	}
	return &Store{root: root, network: network, messages: make(map[messageKey]storedMessage), fatal: make(chan error, 1)}, nil
}

func (s *Store) Accept(encoded []byte) (Envelope, []byte, bool, error) {
	envelope, payload, err := DecodeEnvelope(encoded, s.network)
	if err != nil {
		return Envelope{}, nil, false, err
	}
	key := messageKey{Phase: envelope.Phase, Sender: envelope.SenderIndex}
	digest := sha256.Sum256(encoded)
	s.mu.Lock()
	if previous, exists := s.messages[key]; exists {
		s.mu.Unlock()
		if previous.Digest == digest && bytes.Equal(previous.Encoded, encoded) {
			return envelope, payload, false, nil
		}
		err := fmt.Errorf("%w: phase=%s sender=%d", ErrEquivocation, envelope.Phase, envelope.SenderIndex)
		s.fail(err)
		return Envelope{}, nil, false, err
	}
	phaseDirectory := filepath.Join(s.root, "messages", string(envelope.Phase))
	if err := os.MkdirAll(phaseDirectory, 0o700); err != nil {
		s.mu.Unlock()
		return Envelope{}, nil, false, err
	}
	path := filepath.Join(phaseDirectory, fmt.Sprintf("%02d.json", envelope.SenderIndex))
	if err := writeNew(path, encoded, 0o600); err != nil {
		s.mu.Unlock()
		return Envelope{}, nil, false, err
	}
	s.messages[key] = storedMessage{Envelope: envelope, Payload: append([]byte(nil), payload...), Encoded: append([]byte(nil), encoded...), Digest: digest}
	s.mu.Unlock()
	return envelope, payload, true, nil
}

func (s *Store) PhaseMessages(phase Phase) []storedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storedMessage, 0)
	for key, message := range s.messages {
		if key.Phase == phase {
			copyMessage := message
			copyMessage.Payload = append([]byte(nil), message.Payload...)
			copyMessage.Encoded = append([]byte(nil), message.Encoded...)
			out = append(out, copyMessage)
		}
	}
	return out
}

func (s *Store) Fatal() <-chan error {
	return s.fatal
}

func (s *Store) fail(err error) {
	s.fatalOnce.Do(func() { s.fatal <- err })
}

func (s *Store) Complete(certificateDigest [32]byte) error {
	marker := []byte(fmt.Sprintf("network=%s\nepoch=%d\ntopology=%x\ncertificate=%x\n", s.network.Document.NetworkID, s.network.Document.Epoch, s.network.Digest, certificateDigest))
	if err := writeNew(filepath.Join(s.root, "COMPLETE"), marker, 0o600); err != nil {
		return err
	}
	return os.Rename(filepath.Join(s.root, "RUNNING"), filepath.Join(s.root, "SESSION"))
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
