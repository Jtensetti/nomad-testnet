package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-lifecycle:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("required subcommand: descriptor-init, descriptor-approve, descriptor-activate, descriptor-assemble, epoch-import, plan, revoke-init, revoke-sign or revoke-accept")
	}
	switch arguments[0] {
	case "descriptor-init":
		return descriptorInit(arguments[1:])
	case "descriptor-approve":
		return descriptorSign(arguments[1:], true)
	case "descriptor-activate":
		return descriptorSign(arguments[1:], false)
	case "descriptor-assemble":
		return descriptorAssemble(arguments[1:])
	case "epoch-import":
		return importEpochs(arguments[1:])
	case "plan":
		return plan(arguments[1:])
	case "revoke-init":
		return revokeInit(arguments[1:])
	case "revoke-sign":
		return revokeSign(arguments[1:])
	case "revoke-accept":
		return revokeAccept(arguments[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", arguments[0])
	}
}

type descriptorContext struct {
	Authority ed25519.PublicKey
	Previous  *epoch.Verified
	Revoked   epoch.RevocationSet
}

type descriptorResult struct {
	NetworkID string `json:"network_id"`
	Epoch     uint64 `json:"epoch"`
	Digest    string `json:"descriptor_digest"`
}

func descriptorInit(arguments []string) error {
	flags := flag.NewFlagSet("descriptor-init", flag.ContinueOnError)
	chainPath := flags.String("chain", "", "persisted verified epoch-chain directory")
	revocationPath := flags.String("revocations", "", "persisted accepted-revocation directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	transition := flags.String("transition", "", "genesis, scheduled or emergency")
	activateAt := flags.String("activate-at", "", "public activation boundary in canonical RFC3339")
	retireAt := flags.String("retire-at", "", "public retirement boundary in canonical RFC3339")
	topologyPath := flags.String("topology", "", "authority-signed successor topology")
	certificatePath := flags.String("dkg-certificate", "", "all-operator-certified successor DKG certificate")
	outputPath := flags.String("out", "", "new unsigned descriptor draft")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *chainPath == "" || *revocationPath == "" || *authorityPath == "" || *networkID == "" ||
		*transition == "" || *activateAt == "" || *retireAt == "" || *topologyPath == "" || *certificatePath == "" || *outputPath == "" {
		return errors.New("--chain, --revocations, --authority-key, --network, --transition, --activate-at, --retire-at, --topology, --dkg-certificate and --out are required")
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	topologyBytes, err := readArtifact(*topologyPath, topology.MaximumFileBytes)
	if err != nil {
		return err
	}
	network, err := topology.Verify(topologyBytes, authority, time.Time{})
	if err != nil {
		return fmt.Errorf("verify successor topology: %w", err)
	}
	if network.Document.NetworkID != *networkID {
		return errors.New("successor topology belongs to a different network")
	}
	context, err := loadDescriptorContext(*chainPath, *revocationPath, *authorityPath, *networkID, network.Document.Epoch)
	if err != nil {
		return err
	}
	certificateBytes, err := readArtifact(*certificatePath, committee.MaximumFileBytes)
	if err != nil {
		return err
	}
	descriptor, err := epoch.New(context.Previous, *transition, *activateAt, *retireAt, topologyBytes, certificateBytes)
	if err != nil {
		return err
	}
	verified, err := epoch.ValidateUnsignedDraft(descriptor, context.Authority, context.Previous, context.Revoked)
	if err != nil {
		return err
	}
	encoded, err := epoch.Encode(descriptor)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(descriptorResult{
		NetworkID: verified.NetworkID, Epoch: verified.Epoch, Digest: fmt.Sprintf("%x", verified.Digest),
	})
}

func descriptorSign(arguments []string, approval bool) error {
	name := "descriptor-activate"
	if approval {
		name = "descriptor-approve"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	chainPath := flags.String("chain", "", "persisted verified epoch-chain directory")
	revocationPath := flags.String("revocations", "", "persisted accepted-revocation directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	secretPath := flags.String("secret", "", "local operator secret path")
	journalPath := flags.String("journal", "", "durable local anti-equivocation journal directory")
	inputPath := flags.String("in", "", "unsigned descriptor draft")
	outputPath := flags.String("out", "", "new detached signature artifact")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *chainPath == "" || *revocationPath == "" || *authorityPath == "" || *networkID == "" ||
		*secretPath == "" || *journalPath == "" || *inputPath == "" || *outputPath == "" {
		return errors.New("--chain, --revocations, --authority-key, --network, --secret, --journal, --in and --out are required")
	}
	encodedDraft, err := readArtifact(*inputPath, epoch.MaximumFileBytes)
	if err != nil {
		return err
	}
	descriptor, err := epoch.DecodeDescriptor(encodedDraft)
	if err != nil {
		return err
	}
	claimedNetwork, targetEpoch, err := epoch.DescriptorIdentity(encodedDraft)
	if err != nil {
		return err
	}
	if claimedNetwork != *networkID {
		return errors.New("descriptor draft belongs to a different network")
	}
	context, err := loadDescriptorContext(*chainPath, *revocationPath, *authorityPath, *networkID, targetEpoch)
	if err != nil {
		return err
	}
	keys, err := topology.LoadPrivateKeys(*secretPath)
	if err != nil {
		return err
	}
	journal, err := epoch.OpenJournal(*journalPath)
	if err != nil {
		return err
	}
	var artifact epoch.SignatureArtifact
	if approval {
		artifact, err = journal.CreateApprovalArtifact(descriptor, context.Authority, context.Previous, context.Revoked, keys.OperatorID, keys.Identity)
	} else {
		artifact, err = journal.CreateActivationArtifact(descriptor, context.Authority, context.Previous, context.Revoked, keys.OperatorID, keys.Identity)
	}
	if err != nil {
		return err
	}
	encoded, err := epoch.EncodeSignatureArtifact(artifact)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(artifact)
}

func descriptorAssemble(arguments []string) error {
	flags := flag.NewFlagSet("descriptor-assemble", flag.ContinueOnError)
	chainPath := flags.String("chain", "", "persisted verified epoch-chain directory")
	revocationPath := flags.String("revocations", "", "persisted accepted-revocation directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	inputPath := flags.String("in", "", "unsigned descriptor draft")
	outputPath := flags.String("out", "", "new fully signed descriptor")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *chainPath == "" || *revocationPath == "" || *authorityPath == "" || *networkID == "" || *inputPath == "" || *outputPath == "" || flags.NArg() == 0 {
		return errors.New("--chain, --revocations, --authority-key, --network, --in, --out and one or more signature artifact paths are required")
	}
	encodedDraft, err := readArtifact(*inputPath, epoch.MaximumFileBytes)
	if err != nil {
		return err
	}
	descriptor, err := epoch.DecodeDescriptor(encodedDraft)
	if err != nil {
		return err
	}
	claimedNetwork, targetEpoch, err := epoch.DescriptorIdentity(encodedDraft)
	if err != nil {
		return err
	}
	if claimedNetwork != *networkID {
		return errors.New("descriptor draft belongs to a different network")
	}
	context, err := loadDescriptorContext(*chainPath, *revocationPath, *authorityPath, *networkID, targetEpoch)
	if err != nil {
		return err
	}
	artifacts := make([]epoch.SignatureArtifact, 0, flags.NArg())
	for _, path := range flags.Args() {
		encoded, err := readArtifact(path, epoch.MaximumFileBytes)
		if err != nil {
			return fmt.Errorf("read signature artifact %s: %w", path, err)
		}
		artifact, err := epoch.DecodeSignatureArtifact(encoded)
		if err != nil {
			return fmt.Errorf("decode signature artifact %s: %w", path, err)
		}
		artifacts = append(artifacts, artifact)
	}
	encoded, verified, err := epoch.Assemble(descriptor, artifacts, context.Authority, context.Previous, context.Revoked)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(descriptorResult{
		NetworkID: verified.NetworkID, Epoch: verified.Epoch, Digest: fmt.Sprintf("%x", verified.Digest),
	})
}

func loadDescriptorContext(chainPath, revocationPath, authorityPath, networkID string, targetEpoch uint64) (descriptorContext, error) {
	authority, err := topology.LoadAuthorityKey(authorityPath)
	if err != nil {
		return descriptorContext{}, err
	}
	historical, err := epoch.OpenChain(chainPath, networkID, authority, nil)
	if err != nil {
		return descriptorContext{}, err
	}
	if historical.Halted() {
		return descriptorContext{}, epoch.ErrHalted
	}
	revocations, err := epoch.OpenRevocationStore(revocationPath)
	if err != nil {
		return descriptorContext{}, err
	}
	if err := revocations.Revalidate(historical); err != nil {
		return descriptorContext{}, fmt.Errorf("revalidate persisted revocations: %w", err)
	}
	scope, err := revocations.ScopedSet(targetEpoch)
	if err != nil {
		return descriptorContext{}, err
	}
	chain, err := epoch.OpenChain(chainPath, networkID, authority, scope)
	if err != nil {
		return descriptorContext{}, err
	}
	var previous *epoch.Verified
	if tip, exists := chain.Tip(); exists {
		previous = &tip
	}
	return descriptorContext{Authority: authority, Previous: previous, Revoked: scope}, nil
}

func importEpochs(arguments []string) error {
	flags := flag.NewFlagSet("epoch-import", flag.ContinueOnError)
	chainPath := flags.String("chain", "", "persisted local epoch-chain directory")
	revocationPath := flags.String("revocations", "", "persisted accepted-revocation directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *chainPath == "" || *revocationPath == "" || *authorityPath == "" || *networkID == "" || flags.NArg() == 0 {
		return errors.New("--chain, --revocations, --authority-key, --network and one or more descriptor paths are required")
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	revocations, err := epoch.OpenRevocationStore(*revocationPath)
	if err != nil {
		return err
	}
	// Persisted revocations are not trusted merely because their JSON decodes.
	// Re-verify every stored statement against its exact historical epoch before
	// it may influence admission of a future descriptor.
	historical, err := epoch.OpenChain(*chainPath, *networkID, authority, nil)
	if err != nil {
		return err
	}
	if err := revocations.Revalidate(historical); err != nil {
		return fmt.Errorf("revalidate persisted revocations: %w", err)
	}

	type imported struct {
		Epoch  uint64 `json:"epoch"`
		Digest string `json:"digest"`
	}
	result := make([]imported, 0, flags.NArg())
	for _, path := range flags.Args() {
		encoded, err := readArtifact(path, epoch.MaximumFileBytes)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		claimedNetwork, targetEpoch, err := epoch.DescriptorIdentity(encoded)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if claimedNetwork != *networkID {
			return fmt.Errorf("descriptor %s claims network %q", path, claimedNetwork)
		}
		scope, err := revocations.ScopedSet(targetEpoch)
		if err != nil {
			return err
		}
		chain, err := epoch.OpenChain(*chainPath, *networkID, authority, scope)
		if err != nil {
			return err
		}
		verified, err := chain.Append(encoded)
		if err != nil {
			return fmt.Errorf("append epoch %d from %s: %w", targetEpoch, path, err)
		}
		result = append(result, imported{Epoch: verified.Epoch, Digest: fmt.Sprintf("%x", verified.Digest)})
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Imported []imported `json:"imported"`
	}{result})
}

func plan(arguments []string) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	chainPath := flags.String("chain", "", "persisted local epoch-chain directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	operatorID := flags.String("operator-id", "", "local operator identifier")
	prepareLead := flags.Duration("prepare-lead", 6*time.Hour, "public successor preparation lead")
	retryOffsets := flags.String("retry-offsets", "1h,2h", "comma-separated public retry offsets")
	escalateAfter := flags.Duration("escalate-after", 3*time.Hour, "public escalation offset")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *chainPath == "" || *authorityPath == "" || *networkID == "" || *operatorID == "" {
		return errors.New("--chain, --authority-key, --network and --operator-id are required")
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*chainPath, *networkID, authority, nil)
	if err != nil {
		return err
	}
	offsets, err := parseDurations(*retryOffsets)
	if err != nil {
		return err
	}
	policy := epoch.Policy{PrepareLead: *prepareLead, RetryOffsets: offsets, EscalateAfter: *escalateAfter}
	planned, err := chain.PlanAtForOperator(time.Now().UTC(), policy, *operatorID)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Action  string    `json:"action"`
		Epoch   uint64    `json:"epoch"`
		Attempt int       `json:"attempt"`
		DueAt   time.Time `json:"due_at"`
		Reason  string    `json:"reason"`
	}{planned.Action.String(), planned.Epoch, planned.Attempt, planned.DueAt, planned.Reason})
}

func revokeInit(arguments []string) error {
	flags := flag.NewFlagSet("revoke-init", flag.ContinueOnError)
	chainPath := flags.String("chain", "", "persisted local epoch-chain directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	epochNumber := flags.Uint64("epoch", 0, "epoch in which compromise/revocation was observed")
	targetID := flags.String("target", "", "operator to revoke")
	reason := flags.String("reason", "", "self or compromise")
	outputPath := flags.String("out", "", "new unsigned revocation statement")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *chainPath == "" || *authorityPath == "" || *networkID == "" || *epochNumber == 0 || *targetID == "" || *outputPath == "" {
		return errors.New("--chain, --authority-key, --network, --epoch, --target, --reason and --out are required")
	}
	if *reason != epoch.ReasonSelf && *reason != epoch.ReasonCompromise {
		return errors.New("--reason must be self or compromise")
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*chainPath, *networkID, authority, nil)
	if err != nil {
		return err
	}
	observed, ok, err := chain.FreshEpoch(*epochNumber)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("epoch %d is not stored", *epochNumber)
	}
	target, ok := findOperator(observed.Topology, *targetID)
	if !ok {
		return fmt.Errorf("operator %q is not in epoch %d", *targetID, *epochNumber)
	}
	revocation := epoch.Revocation{
		Version: epoch.RevocationVersion, NetworkID: *networkID,
		OperatorID: target.ID, IdentityKey: target.IdentityKey,
		EpochObserved: observed.Epoch, Reason: *reason,
	}
	encoded, err := epoch.EncodeRevocation(revocation)
	if err != nil {
		return err
	}
	return writeNew(*outputPath, encoded, 0o644)
}

func revokeSign(arguments []string) error {
	flags := flag.NewFlagSet("revoke-sign", flag.ContinueOnError)
	secretPath := flags.String("secret", "", "local operator secret path")
	chainPath := flags.String("chain", "", "persisted local epoch-chain directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	inputPath := flags.String("in", "", "revocation statement to sign")
	outputPath := flags.String("out", "", "new signed revocation statement")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *secretPath == "" || *chainPath == "" || *authorityPath == "" || *networkID == "" || *inputPath == "" || *outputPath == "" {
		return errors.New("--secret, --chain, --authority-key, --network, --in and --out are required")
	}
	encoded, err := readArtifact(*inputPath, epoch.MaximumFileBytes)
	if err != nil {
		return err
	}
	revocation, err := epoch.DecodeRevocation(encoded)
	if err != nil {
		return err
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*chainPath, *networkID, authority, nil)
	if err != nil {
		return err
	}
	observed, ok, err := chain.FreshEpoch(revocation.EpochObserved)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("observed epoch %d is not stored", revocation.EpochObserved)
	}
	if err := validatePartialRevocation(revocation, observed); err != nil {
		return err
	}
	keys, err := topology.LoadPrivateKeys(*secretPath)
	if err != nil {
		return err
	}
	signer, ok := findOperator(observed.Topology, keys.OperatorID)
	if !ok {
		return fmt.Errorf("local operator %q is not in observed epoch", keys.OperatorID)
	}
	public := base64.StdEncoding.EncodeToString(keys.Identity.Public().(ed25519.PublicKey))
	if public != signer.IdentityKey {
		return errors.New("local identity key does not match observed epoch membership")
	}
	for _, existing := range revocation.Signatures {
		if existing.OperatorID == keys.OperatorID {
			return errors.New("local operator already signed this revocation")
		}
	}
	if revocation.Reason == epoch.ReasonSelf && keys.OperatorID != revocation.OperatorID {
		return errors.New("self-revocation may only be signed by the target")
	}
	if revocation.Reason == epoch.ReasonCompromise && keys.OperatorID == revocation.OperatorID {
		return errors.New("target signature does not count for compromise revocation; refusing misleading signature")
	}
	signed, err := epoch.SignRevocation(revocation, keys.OperatorID, keys.Identity)
	if err != nil {
		return err
	}
	result, err := epoch.EncodeRevocation(signed)
	if err != nil {
		return err
	}
	return writeNew(*outputPath, result, 0o644)
}

func revokeAccept(arguments []string) error {
	flags := flag.NewFlagSet("revoke-accept", flag.ContinueOnError)
	storePath := flags.String("store", "", "persisted accepted-revocation directory")
	chainPath := flags.String("chain", "", "persisted local epoch-chain directory")
	authorityPath := flags.String("authority-key", "", "pinned authority public-key path")
	networkID := flags.String("network", "", "network identifier")
	inputPath := flags.String("in", "", "fully authorized revocation statement")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *storePath == "" || *chainPath == "" || *authorityPath == "" || *networkID == "" || *inputPath == "" {
		return errors.New("--store, --chain, --authority-key, --network and --in are required")
	}
	encoded, err := readArtifact(*inputPath, epoch.MaximumFileBytes)
	if err != nil {
		return err
	}
	revocation, err := epoch.DecodeRevocation(encoded)
	if err != nil {
		return err
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*chainPath, *networkID, authority, nil)
	if err != nil {
		return err
	}
	observed, ok, err := chain.FreshEpoch(revocation.EpochObserved)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("observed epoch %d is not stored", revocation.EpochObserved)
	}
	store, err := epoch.OpenRevocationStore(*storePath)
	if err != nil {
		return err
	}
	if err := store.Revalidate(chain); err != nil {
		return fmt.Errorf("revalidate persisted revocations: %w", err)
	}
	if err := store.Accept(encoded, observed); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID    string `json:"operator_id"`
		EpochObserved uint64 `json:"epoch_observed"`
		Reason        string `json:"reason"`
	}{revocation.OperatorID, revocation.EpochObserved, revocation.Reason})
}

func validatePartialRevocation(revocation epoch.Revocation, observed epoch.Verified) error {
	if revocation.NetworkID != observed.NetworkID || revocation.EpochObserved != observed.Epoch {
		return errors.New("revocation does not match the supplied observed epoch")
	}
	target, ok := findOperator(observed.Topology, revocation.OperatorID)
	if !ok || target.IdentityKey != revocation.IdentityKey {
		return errors.New("revocation target does not match observed membership")
	}
	message, err := epoch.RevocationMessage(revocation)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(revocation.Signatures))
	for _, signed := range revocation.Signatures {
		if _, duplicate := seen[signed.OperatorID]; duplicate {
			return errors.New("duplicate revocation signer")
		}
		seen[signed.OperatorID] = struct{}{}
		operator, ok := findOperator(observed.Topology, signed.OperatorID)
		if !ok {
			return fmt.Errorf("revocation signer %q is not in observed membership", signed.OperatorID)
		}
		public, err := base64.StdEncoding.Strict().DecodeString(operator.IdentityKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return errors.New("invalid observed identity key")
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(signed.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
			return fmt.Errorf("invalid existing revocation signature from %s", signed.OperatorID)
		}
	}
	return nil
}

func findOperator(network topology.Verified, id string) (topology.Operator, bool) {
	for _, operator := range network.Document.Operators {
		if operator.ID == id {
			return operator, true
		}
	}
	return topology.Operator{}, false
}

func parseDurations(encoded string) ([]time.Duration, error) {
	parts := strings.Split(encoded, ",")
	result := make([]time.Duration, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := time.ParseDuration(part)
		if err != nil {
			return nil, fmt.Errorf("invalid retry offset %q: %w", part, err)
		}
		result = append(result, value)
	}
	return result, nil
}

func readArtifact(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("input must be a non-empty bounded regular file")
	}
	return os.ReadFile(path)
}

func writeNew(path string, content []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output parent must be a real directory")
	}
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
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
