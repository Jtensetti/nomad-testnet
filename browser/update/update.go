// Package update verifies a release before it is installed, and refuses one
// that would move the installation backwards.
//
// The shape of this package is dictated by what the browser is. A networkless
// browser cannot contain an updater that fetches, because an updater that
// fetches is a network client inside the binary that is supposed to have none,
// and every guarantee downstream of "this process cannot open a socket" would
// then rest on that one component behaving. So nothing here downloads
// anything. A release arrives out of band -- the user fetches a disk image the
// way they fetch anything else -- and this package answers one question about
// the bytes they already have: may this be installed over what is installed
// now?
//
// That division is enforced rather than intended: the package imports no
// network capability, and a test in this repository fails if its transitive
// graph ever gains one.
//
// Everything here fails closed. A release that cannot be verified is refused;
// it never becomes a warning, a prompt, or an install that proceeds anyway.
// The three ways an update mechanism is normally attacked are each refused by
// name rather than by accident:
//
//   - Rollback: a signed but older release, replayed to move a user back to a
//     version whose flaws are known. Refused against a persisted watermark.
//   - Equivocation: two validly signed releases carrying the same version and
//     different artefacts. Refused rather than resolved, because picking
//     either one silently is how a targeted build reaches one user.
//   - Substitution: a valid manifest paired with a different artefact. Refused
//     by comparing the artefact's digest against the signed one.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// ManifestVersion is the frozen wire label for a release manifest.
	//
	// v2 replaces v1's single signature with a set of approvals. A documented
	// two-person release process holds only as long as everyone remembers it;
	// requiring two signatures from two distinct trusted keys makes it a
	// control enforced at the point of installation, by the machine that would
	// otherwise be defrauded.
	//
	// No release key exists yet and nothing has ever shipped, so there is no
	// v1 manifest to stay compatible with. An unrecognised version is refused
	// rather than downgraded to, so a v1 manifest presented to this build
	// fails closed.
	ManifestVersion = "nomad-browser-release-v2"

	// MinimumApprovals is the two in "two-person release process".
	MinimumApprovals = 2
	// signingLabel domain-separates the release signature from every other
	// signature this project makes.
	signingLabel = "nomad-browser-release-manifest-v1"
	// MaximumManifestBytes bounds a manifest before it is parsed.
	MaximumManifestBytes = 64 << 10
)

var (
	// ErrRollback reports a release no newer than the one installed.
	ErrRollback = errors.New("release would move the installation backwards")
	// ErrEquivocation reports two different artefacts claiming one version.
	ErrEquivocation = errors.New("two different releases claim the same version")
	// ErrUnverified reports a manifest that does not verify. It is terminal:
	// there is no path from here to an install.
	ErrUnverified = errors.New("release manifest does not verify")
	// ErrArtifactMismatch reports an artefact that is not the one signed.
	ErrArtifactMismatch = errors.New("artifact does not match the signed digest")
)

// Version is a release version ordered by (major, minor, patch), with
// pre-release builds ordered before the release they lead to.
//
// Pre-release ordering matters here for one reason: an alpha must never be
// installable over the final build of the same version, or a signed alpha
// becomes a downgrade vector.
type Version struct {
	Major, Minor, Patch uint32
	// Pre is the pre-release label, empty for a final release. Two
	// pre-releases of one version are ordered lexically, which is enough to
	// keep alpha before beta and both before the final.
	Pre string
}

// ParseVersion reads "1.2.3" or "1.2.3-alpha.4".
func ParseVersion(text string) (Version, error) {
	var version Version
	core, pre, _ := strings.Cut(text, "-")
	fields := strings.Split(core, ".")
	if len(fields) != 3 {
		return version, fmt.Errorf("version %q is not major.minor.patch", text)
	}
	numbers := make([]uint32, 3)
	for index, field := range fields {
		if field == "" || (len(field) > 1 && field[0] == '0') {
			// A leading zero makes "1.02.3" and "1.2.3" two spellings of one
			// version, and two spellings is one too many for something a
			// rollback check compares.
			return version, fmt.Errorf("version %q has a non-canonical component %q", text, field)
		}
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return version, fmt.Errorf("version %q has a non-numeric component %q", text, field)
		}
		numbers[index] = uint32(value)
	}
	version = Version{Major: numbers[0], Minor: numbers[1], Patch: numbers[2], Pre: pre}
	if strings.ContainsAny(pre, " \t\n") {
		return Version{}, fmt.Errorf("version %q has whitespace in its pre-release label", text)
	}
	return version, nil
}

func (v Version) String() string {
	core := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre == "" {
		return core
	}
	return core + "-" + v.Pre
}

// Compare returns -1, 0 or 1.
func (v Version) Compare(other Version) int {
	for _, pair := range [][2]uint32{
		{v.Major, other.Major}, {v.Minor, other.Minor}, {v.Patch, other.Patch},
	} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == other.Pre:
		return 0
	case v.Pre == "":
		// A final release is newer than any pre-release of itself.
		return 1
	case other.Pre == "":
		return -1
	case v.Pre < other.Pre:
		return -1
	default:
		return 1
	}
}

// Manifest is the signed statement about one release.
type Manifest struct {
	Version      string `json:"version"`
	Release      string `json:"release"`
	Channel      string `json:"channel"`
	ArtifactName string `json:"artifact_name"`
	// ArtifactDigest is the hex SHA-256 of the installer.
	ArtifactDigest string `json:"artifact_digest"`
	ArtifactBytes  int64  `json:"artifact_bytes"`
	// Approvals are the release approvers' signatures over everything above.
	// Order is not significant and is not part of the signed message.
	Approvals []Approval `json:"approvals"`
}

// Approval is one approver's signature over a release.
type Approval struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// Verified is a manifest that has been checked. It is the only way to reach a
// release's fields, so nothing downstream can act on an unverified one.
type Verified struct {
	Manifest Manifest
	Release  Version
	Digest   [32]byte
	Channel  string
	// Approvers are the distinct trusted keys that approved this release, in
	// the order the trusted set gave them. Recorded so a release decision can
	// say who approved it rather than only that enough people did.
	Approvers []string
}

// Decode parses and verifies a manifest against the release public key the
// caller trusts.
//
// The trusted key is a parameter rather than a field in the manifest: a
// manifest that names its own key authenticates nothing, because an attacker
// substituting the whole manifest substitutes the key with it.
func Decode(encoded []byte, trusted []ed25519.PublicKey) (Verified, error) {
	if len(encoded) == 0 || int64(len(encoded)) > MaximumManifestBytes {
		return Verified{}, fmt.Errorf("%w: manifest is empty or oversize", ErrUnverified)
	}
	approvers, err := distinctApprovers(trusted)
	if err != nil {
		return Verified{}, err
	}

	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Verified{}, fmt.Errorf("%w: trailing data after the manifest", ErrUnverified)
	}
	if manifest.Version != ManifestVersion {
		return Verified{}, fmt.Errorf("%w: unrecognised manifest version %q, which is refused "+
			"rather than downgraded to a version this build understands",
			ErrUnverified, manifest.Version)
	}

	release, err := ParseVersion(manifest.Release)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	digest, err := hex.DecodeString(manifest.ArtifactDigest)
	if err != nil || len(digest) != sha256.Size {
		return Verified{}, fmt.Errorf("%w: malformed artifact digest", ErrUnverified)
	}
	if manifest.ArtifactBytes <= 0 {
		return Verified{}, fmt.Errorf("%w: artifact size must be positive", ErrUnverified)
	}
	if manifest.Channel == "" || manifest.ArtifactName == "" {
		return Verified{}, fmt.Errorf("%w: manifest is missing its channel or artifact name", ErrUnverified)
	}
	if strings.ContainsAny(manifest.ArtifactName, "/\\") || manifest.ArtifactName == ".." {
		// The name is used to locate a file next to the manifest, so it must
		// not be able to name somewhere else.
		return Verified{}, fmt.Errorf("%w: artifact name is a path", ErrUnverified)
	}
	if len(manifest.Approvals) > len(approvers) {
		return Verified{}, fmt.Errorf("%w: %d approvals against %d trusted keys",
			ErrUnverified, len(manifest.Approvals), len(approvers))
	}

	message := signingMessage(manifest)
	// Count distinct *approvers*, not signatures. Two signatures from one key
	// are one person signing twice, which is the whole thing a two-person rule
	// exists to prevent, and it is the cheapest way to defeat a scheme that
	// counts signatures.
	satisfied := map[string]bool{}
	for _, approval := range manifest.Approvals {
		declared, err := hex.DecodeString(approval.PublicKey)
		if err != nil || len(declared) != ed25519.PublicKeySize {
			return Verified{}, fmt.Errorf("%w: malformed approver key", ErrUnverified)
		}
		signature, err := hex.DecodeString(approval.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize {
			return Verified{}, fmt.Errorf("%w: malformed approval signature", ErrUnverified)
		}
		index, trustedKey := matchTrusted(approvers, declared)
		if index < 0 {
			return Verified{}, fmt.Errorf("%w: approved by a key this build does not trust",
				ErrUnverified)
		}
		if !ed25519.Verify(trustedKey, message, signature) {
			return Verified{}, fmt.Errorf("%w: approval by %s does not verify",
				ErrUnverified, approval.PublicKey[:16])
		}
		if satisfied[approval.PublicKey] {
			return Verified{}, fmt.Errorf("%w: the same approver signed twice, which is one "+
				"person, not two", ErrUnverified)
		}
		satisfied[approval.PublicKey] = true
	}
	if len(satisfied) < MinimumApprovals {
		return Verified{}, fmt.Errorf("%w: %d distinct approvals, and a release needs %d",
			ErrUnverified, len(satisfied), MinimumApprovals)
	}

	verified := Verified{Manifest: manifest, Release: release, Channel: manifest.Channel}
	copy(verified.Digest[:], digest)
	for _, key := range approvers {
		encodedKey := hex.EncodeToString(key)
		if satisfied[encodedKey] {
			verified.Approvers = append(verified.Approvers, encodedKey)
		}
	}
	return verified, nil
}

// distinctApprovers checks the trusted set itself. A set that lists one key
// twice would let one person satisfy a two-person rule without any of the
// checks below noticing, because each signature would match a different entry.
func distinctApprovers(trusted []ed25519.PublicKey) ([]ed25519.PublicKey, error) {
	if len(trusted) < MinimumApprovals {
		return nil, fmt.Errorf("%w: %d trusted release keys, and a two-person process needs %d",
			ErrUnverified, len(trusted), MinimumApprovals)
	}
	seen := map[string]bool{}
	for _, key := range trusted {
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: a trusted release key is malformed", ErrUnverified)
		}
		encoded := hex.EncodeToString(key)
		if seen[encoded] {
			return nil, fmt.Errorf("%w: the trusted release keys are not distinct, so one "+
				"approver could satisfy the rule alone", ErrUnverified)
		}
		seen[encoded] = true
	}
	return trusted, nil
}

func matchTrusted(trusted []ed25519.PublicKey, declared []byte) (int, ed25519.PublicKey) {
	for index, key := range trusted {
		if subtle.ConstantTimeCompare(key, declared) == 1 {
			return index, key
		}
	}
	return -1, nil
}

// Prepare stamps a manifest with the current format version and clears any
// approvals it arrived with. It is here so the format has exactly one
// implementation and a test cannot accidentally build something the verifier
// would not have accepted.
//
// It replaces a Sign that took the one release key. There is no such key any
// more: a release is not signed by the project, it is approved by people, and
// the function that turns a manifest into a signed one is Approve.
func Prepare(manifest Manifest) Manifest {
	manifest.Version = ManifestVersion
	manifest.Approvals = nil
	return manifest
}

// Approve adds one approver's signature to a manifest. Signing and approving
// are separate calls because they are separate people: a function that took
// two keys at once would be a two-person process one person can run.
func Approve(manifest Manifest, key ed25519.PrivateKey) (Manifest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("an approver private key is required")
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return Manifest{}, errors.New("approver key does not carry a public half")
	}
	unsigned := manifest
	unsigned.Approvals = nil
	signature := ed25519.Sign(key, signingMessage(unsigned))
	manifest.Approvals = append(append([]Approval(nil), manifest.Approvals...), Approval{
		PublicKey: hex.EncodeToString(public),
		Signature: hex.EncodeToString(signature),
	})
	return manifest, nil
}

// signingMessage covers every field except the approvals, each length
// prefixed so no two different manifests can produce one message. Approvals
// are excluded so that every approver signs the same bytes regardless of who
// signed first or how many have signed.
func signingMessage(manifest Manifest) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(signingLabel))
	for _, field := range []string{
		manifest.Version, manifest.Release, manifest.Channel,
		manifest.ArtifactName, manifest.ArtifactDigest,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(field))
	}
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(manifest.ArtifactBytes))
	_, _ = h.Write(size[:])
	return h.Sum(nil)
}

// Watermark is the record of what has been installed. It is what makes a
// rollback detectable at all: without it, a signed older release is
// indistinguishable from a signed newer one.
type Watermark struct {
	Version string `json:"version"`
	Digest  string `json:"artifact_digest"`
	Channel string `json:"channel"`
}

// AcceptMonotonic decides whether a verified release may be installed over
// whatever the watermark at path records, and on success advances it.
//
// A missing watermark is a first install and is accepted. A watermark that
// exists but cannot be read is **not** treated as missing: an attacker who can
// corrupt a file must not be able to turn rollback protection off by doing so.
func AcceptMonotonic(path string, release Verified) error {
	installed, err := readWatermark(path)
	if err != nil {
		return err
	}
	if installed != nil {
		if installed.Channel != release.Channel {
			return fmt.Errorf("%w: installed from channel %q, offered %q",
				ErrRollback, installed.Channel, release.Channel)
		}
		current, err := ParseVersion(installed.Version)
		if err != nil {
			return fmt.Errorf("stored watermark is unreadable: %w", err)
		}
		switch release.Release.Compare(current) {
		case -1:
			return fmt.Errorf("%w: %s is older than the installed %s",
				ErrRollback, release.Release, current)
		case 0:
			if installed.Digest != hex.EncodeToString(release.Digest[:]) {
				// Same version, different artefact. Both may be validly
				// signed; that is exactly why this is refused rather than
				// resolved.
				return fmt.Errorf("%w: version %s is installed with digest %s and this "+
					"release carries %x", ErrEquivocation, current,
					installed.Digest[:16], release.Digest[:8])
			}
			return fmt.Errorf("%w: %s is already installed", ErrRollback, current)
		}
	}
	return writeWatermark(path, Watermark{
		Version: release.Release.String(),
		Digest:  hex.EncodeToString(release.Digest[:]),
		Channel: release.Channel,
	})
}

// InstalledVersion reports what the watermark records, or nil for a machine
// with no install.
func InstalledVersion(path string) (*Version, error) {
	installed, err := readWatermark(path)
	if err != nil || installed == nil {
		return nil, err
	}
	version, err := ParseVersion(installed.Version)
	if err != nil {
		return nil, fmt.Errorf("stored watermark is unreadable: %w", err)
	}
	return &version, nil
}

func readWatermark(path string) (*Watermark, error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read install watermark: %w", err)
	}
	var installed Watermark
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&installed); err != nil {
		// Refused, not ignored: treating an unreadable watermark as absent
		// would let anyone who can corrupt one file disable rollback
		// protection.
		return nil, fmt.Errorf("install watermark is unreadable, so rollback protection "+
			"cannot be applied and this install is refused: %w", err)
	}
	if installed.Version == "" || installed.Digest == "" || installed.Channel == "" {
		return nil, errors.New("install watermark is incomplete, so rollback protection " +
			"cannot be applied and this install is refused")
	}
	return &installed, nil
}

func writeWatermark(path string, watermark Watermark) error {
	encoded, err := json.MarshalIndent(watermark, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	// Rename so a crash between write and rename leaves the previous
	// watermark intact rather than a truncated one, which readWatermark would
	// refuse and which would then block every future install.
	return os.Rename(temporary, path)
}

// VerifyArtifact checks the installer the user already has against the signed
// manifest. It reads in bounded chunks and stops at the declared size, so a
// file that grew past what was signed is refused rather than streamed.
func VerifyArtifact(path string, release Verified) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArtifactMismatch, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArtifactMismatch, err)
	}
	if info.Size() != release.Manifest.ArtifactBytes {
		return fmt.Errorf("%w: artifact is %d bytes, the manifest signs %d",
			ErrArtifactMismatch, info.Size(), release.Manifest.ArtifactBytes)
	}
	hasher := sha256.New()
	if _, err := io.CopyN(hasher, file, release.Manifest.ArtifactBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrArtifactMismatch, err)
	}
	var actual [32]byte
	copy(actual[:], hasher.Sum(nil))
	if subtle.ConstantTimeCompare(actual[:], release.Digest[:]) != 1 {
		return fmt.Errorf("%w: artifact hashes to %x, the manifest signs %x",
			ErrArtifactMismatch, actual[:8], release.Digest[:8])
	}
	return nil
}
