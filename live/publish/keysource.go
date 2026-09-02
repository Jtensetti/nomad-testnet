package publish

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/Jtensetti/nomad-testnet/live/durable"
)

// KeySource supplies the key the queue seals pending fragments under.
//
// There is no default. The two sources differ in what a stolen disk yields,
// which is the whole question for material a user has written but not yet
// published, so a caller states which one it is accepting rather than
// inheriting one.
type KeySource interface {
	openKey(root string) ([32]byte, error)
}

const (
	saltFileName     = "queue.salt"
	verifierFileName = "queue.check"
	saltSize         = 16

	// Argon2id parameters. This derivation runs once when a publisher opens
	// its queue, not per request, so the memory cost is set well above what an
	// interactive login could afford: 64 MiB is what an attacker must hold per
	// guess, and memory is the parameter that costs a GPU or an ASIC, where
	// passes alone do not.
	//
	// Changing any of them changes the derived key, so an existing queue
	// stops opening. The salt record carries the parameters it was created
	// under for exactly that reason: a future change is then a mismatch that
	// says so, rather than a wrong-passphrase error sending an operator to
	// retype something that was never wrong.
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4

	keyDerivationDomain = "nomad-publication-queue-key-v1"
	verifierPlaintext   = "nomad-publication-queue-verifier-v1"
)

// ErrPassphraseRejected reports a passphrase that does not open this queue.
//
// It is reported at Open rather than left to surface as an unreadable
// fragment. A publisher that opened a queue it cannot decrypt would look
// exactly like a publisher with nothing to publish -- Drain treats every
// Next error as "no work", deliberately, so that an idle publisher and a
// busy one are indistinguishable -- and would emit cover forever while its
// queue filled up.
var ErrPassphraseRejected = errors.New("passphrase does not open this publication queue")

type passphraseSource struct{ passphrase []byte }

// Passphrase derives the queue key from a passphrase with Argon2id.
//
// What the disk then holds is the sealed fragments, a salt and a verifier.
// A salt is not a secret and the verifier is a known plaintext, so nothing on
// the disk is the key or leads to it without the passphrase: a stolen disk
// yields the queue and no way to open it. That is the property
// UnprotectedKeyFile does not have.
//
// There is no way to change a queue's passphrase. Doing so means opening every
// stored fragment under the old key and sealing it under the new one, and a
// re-key that is interrupted part-way leaves a queue whose fragments are under
// two keys. Not implemented rather than half-implemented; a publisher that
// needs a new passphrase drains its queue and creates a new one.
//
// What it does not protect: a running publisher holds the derived key in
// memory, so this is a control on the disk at rest and not on the process.
func Passphrase(passphrase []byte) KeySource {
	copied := make([]byte, len(passphrase))
	copy(copied, passphrase)
	return passphraseSource{passphrase: copied}
}

func (source passphraseSource) openKey(root string) ([32]byte, error) {
	var key [32]byte
	if len(source.passphrase) == 0 {
		return key, errors.New("publication queue passphrase is required")
	}
	if err := refuseOtherSource(root, keyFileName,
		"this queue was created with --key-source=unprotected-file"); err != nil {
		return key, err
	}
	salt, err := loadOrCreateSalt(root)
	if err != nil {
		return key, err
	}
	derived := argon2.IDKey([]byte(keyDerivationDomain+string(source.passphrase)),
		salt, argonTime, argonMemory, argonThreads, 32)
	copy(key[:], derived)
	if err := checkOrCreateVerifier(root, key); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

// saltRecord is the on-disk salt: a magic string, the three Argon2id
// parameters the queue was created under, then the salt itself.
//
//	version | time uint32 | memory uint32 | threads uint32 | salt[16]
const saltRecordVersion = "nomad-publication-queue-salt-v1"

const saltRecordSize = len(saltRecordVersion) + 12 + saltSize

var saltMagic = []byte(saltRecordVersion)

func encodeSaltRecord(salt []byte) []byte {
	record := make([]byte, 0, saltRecordSize)
	record = append(record, saltMagic...)
	record = binary.BigEndian.AppendUint32(record, argonTime)
	record = binary.BigEndian.AppendUint32(record, argonMemory)
	record = binary.BigEndian.AppendUint32(record, argonThreads)
	return append(record, salt...)
}

func decodeSaltRecord(record []byte) ([]byte, error) {
	// A salt that changed derives a different key and leaves every stored
	// fragment unopenable, so a malformed record is refused rather than
	// padded or regenerated over the top of a queue that still has work in it.
	if len(record) != saltRecordSize || !bytes.Equal(record[:len(saltMagic)], saltMagic) {
		return nil, errors.New("publication queue salt is malformed")
	}
	fields := record[len(saltMagic):]
	time := binary.BigEndian.Uint32(fields[0:4])
	memory := binary.BigEndian.Uint32(fields[4:8])
	threads := binary.BigEndian.Uint32(fields[8:12])
	if time != argonTime || memory != argonMemory || threads != argonThreads {
		return nil, fmt.Errorf("publication queue salt was created under Argon2id "+
			"t=%d m=%d p=%d and this build derives keys with t=%d m=%d p=%d, "+
			"which opens nothing", time, memory, threads,
			argonTime, argonMemory, argonThreads)
	}
	return fields[12:], nil
}

// loadOrCreateSalt reads the queue's salt record, creating it if this is the
// first open.
//
// The create is exclusive and the loser of a race re-reads rather than
// failing: two publishers opening one queue must agree on the salt, since a
// salt that is replaced after another opener has derived from it leaves that
// opener writing fragments nothing can later read.
func loadOrCreateSalt(root string) ([]byte, error) {
	path := filepath.Join(root, saltFileName)
	for attempt := 0; attempt < 2; attempt++ {
		existing, err := os.ReadFile(path)
		if err == nil {
			return decodeSaltRecord(existing)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		err = createExclusive(path, encodeSaltRecord(salt))
		if err == nil {
			return salt, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("publication queue salt could not be read or created")
}

// createExclusive publishes data at path without ever clobbering what is
// already there, and without another reader seeing a partial file.
//
// O_EXCL alone gives the first property and not the second: a concurrent
// opener that reads between the create and the write sees an empty file and
// refuses it as malformed, which is what a first version of this did and what
// TestConcurrentOpensAgreeOnTheKey caught. So the content is written to a
// temporary file first and then linked into place, which is atomic and fails
// with ErrExist rather than replacing an existing name -- unlike rename, which
// silently would.
func createExclusive(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".publish-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	return durable.Directory(directory)
}

func checkOrCreateVerifier(root string, key [32]byte) error {
	sealed, err := sealVerifier(key)
	if err != nil {
		return err
	}
	path := filepath.Join(root, verifierFileName)
	existing, err := os.ReadFile(path)
	if err == nil {
		// The seal is deterministic under one key, so equality settles it.
		if subtle.ConstantTimeCompare(existing, sealed) != 1 {
			return ErrPassphraseRejected
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The loser of a race against another opener holding the same passphrase
	// wrote the identical verifier, so an exists error is agreement.
	if err := createExclusive(path, sealed); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// sealVerifier seals a known plaintext under the derived key. The nonce is
// fixed because exactly one message is ever sealed under this key at this
// domain, so it cannot repeat for a different plaintext.
func sealVerifier(key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(verifierPlaintext))
	nonce := digest[:aead.NonceSize()]
	return aead.Seal(nil, nonce, []byte(verifierPlaintext), nil), nil
}

// ErrKeySourceMismatch reports a queue opened under a different key source
// than the one that created it.
//
// It is refused rather than allowed to derive a key that opens nothing.
// Drain treats every Queue.Next error as "no work" by design, so a publisher
// holding a queue it cannot decrypt is indistinguishable from an idle one and
// would emit cover forever while its queue filled -- the same failure a wrong
// passphrase would cause, arriving through the flag instead.
var ErrKeySourceMismatch = errors.New("publication queue was created under a different key source")

func refuseOtherSource(root, marker, detail string) error {
	if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
		return fmt.Errorf("%w: %s", ErrKeySourceMismatch, detail)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type unprotectedKeyFile struct{}

// UnprotectedKeyFile keeps a random key in queue.key inside the queue
// directory, beside the fragments it encrypts.
//
// It is named for what it is. A disk that carries the fragments carries the
// key, so this is not protection against a stolen disk and must not be
// described as if it were. What it does give is binding -- every fragment is
// sealed under its own identifier as additional data, so one cannot be
// renamed, altered or moved between queues -- and a barrier against a copy
// that takes the fragments and not the key.
//
// Use Passphrase where the disk is part of the threat.
func UnprotectedKeyFile() KeySource { return unprotectedKeyFile{} }

func (unprotectedKeyFile) openKey(root string) ([32]byte, error) {
	var key [32]byte
	if err := refuseOtherSource(root, saltFileName,
		"this queue was created with --key-source=passphrase"); err != nil {
		return key, err
	}
	path := filepath.Join(root, keyFileName)
	existing, err := os.ReadFile(path)
	if err == nil {
		if len(existing) != len(key) {
			return key, errors.New("publication queue key is malformed")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return key, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return key, errors.New("publication queue key permissions must be 0600 or stricter")
		}
		copy(key[:], existing)
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	if err := writeNewFile(path, key[:], 0o600); err != nil {
		return key, err
	}
	return key, nil
}
