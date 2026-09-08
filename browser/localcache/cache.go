package localcache

import (
	"bytes"
	"errors"
	"sync"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
)

var ErrNotFound = errors.New("verified object not found")

type Object struct {
	Manifest reconstruct.Manifest
	Bytes    []byte
}

type Reader interface {
	Get([32]byte) (Object, error)
}

// Memory is an immutable-by-key cache for objects that have already crossed
// the private reconstruction boundary. It has no network or query callback.
type Memory struct {
	mu      sync.RWMutex
	objects map[[32]byte]Object
}

func NewMemory() *Memory {
	return &Memory{objects: make(map[[32]byte]Object)}
}

func (m *Memory) Put(manifest reconstruct.Manifest, data []byte) error {
	if m == nil {
		return errors.New("cache is nil")
	}
	if err := manifest.VerifyObject(data); err != nil {
		return err
	}
	object := Object{Manifest: manifest, Bytes: append([]byte(nil), data...)}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.objects[manifest.Root]; ok {
		if existing.Manifest != manifest || !bytes.Equal(existing.Bytes, data) {
			return errors.New("object commitment already has different immutable metadata")
		}
		return nil
	}
	m.objects[manifest.Root] = object
	return nil
}

func (m *Memory) Get(root [32]byte) (Object, error) {
	if m == nil {
		return Object{}, ErrNotFound
	}
	m.mu.RLock()
	object, ok := m.objects[root]
	m.mu.RUnlock()
	if !ok {
		return Object{}, ErrNotFound
	}
	if err := object.Manifest.VerifyObject(object.Bytes); err != nil {
		return Object{}, err
	}
	object.Bytes = append([]byte(nil), object.Bytes...)
	return object, nil
}
