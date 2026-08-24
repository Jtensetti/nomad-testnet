package epoch

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func unsignedDescriptor(verified Verified) Descriptor {
	descriptor := verified.Descriptor
	descriptor.Approvals = nil
	descriptor.Activations = nil
	return descriptor
}

func TestIndependentDetachedSignatureAssembly(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	draft := unsignedDescriptor(successor)
	artifacts := make([]SignatureArtifact, 0, ApprovalQuorum(genesis)+len(f.Operators))

	for index := 0; index < ApprovalQuorum(genesis); index++ {
		journal, err := OpenJournal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := journal.CreateApprovalArtifact(
			draft, f.AuthorityPublic, &genesis, nil,
			f.Operators[index].ID, f.Operators[index].Identity,
		)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeSignatureArtifact(artifact)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeSignatureArtifact(encoded)
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, decoded)
	}
	for index := range f.Operators {
		journal, err := OpenJournal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := journal.CreateActivationArtifact(
			draft, f.AuthorityPublic, &genesis, nil,
			f.Operators[index].ID, f.Operators[index].Identity,
		)
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, artifact)
	}

	encoded, assembled, err := Assemble(draft, artifacts, f.AuthorityPublic, &genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if assembled.Digest != successor.Digest {
		t.Fatal("detached assembly changed the reviewed descriptor digest")
	}
	if _, err := Verify(encoded, f.AuthorityPublic, &genesis, nil); err != nil {
		t.Fatalf("assembled descriptor did not pass final admission: %v", err)
	}
}

func TestSignerValidatesDraftBeforeBurningJournalSlot(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	draft := unsignedDescriptor(successor)
	draft.PreviousEpochDigest = strings.Repeat("00", 32)
	root := t.TempDir()
	journal, err := OpenJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CreateActivationArtifact(
		draft, f.AuthorityPublic, &genesis, nil,
		f.Operators[0].ID, f.Operators[0].Identity,
	); err == nil {
		t.Fatal("invalid draft was signed")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("invalid draft burned a durable anti-equivocation journal slot")
	}
}

func TestDetachedSignerRefusesPrefilledSignatureSets(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	draft := unsignedDescriptor(successor)
	draft.Activations = []Activation{{OperatorID: "attacker"}}
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CreateApprovalArtifact(
		draft, f.AuthorityPublic, &genesis, nil,
		f.Operators[0].ID, f.Operators[0].Identity,
	); err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("prefilled signature set was not rejected: %v", err)
	}
}

func TestDetachedSignatureCannotBeTransplantedToAnotherDraft(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	draft := unsignedDescriptor(successor)
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := journal.CreateActivationArtifact(
		draft, f.AuthorityPublic, &genesis, nil,
		f.Operators[0].ID, f.Operators[0].Identity,
	)
	if err != nil {
		t.Fatal(err)
	}

	other := draft
	other.RetireAt = canonicalTime(successor.RetireAt.Add(time.Minute))
	if _, _, err := Assemble(other, []SignatureArtifact{artifact}, f.AuthorityPublic, &genesis, nil); err == nil || !strings.Contains(err.Error(), "different epoch descriptor") {
		t.Fatalf("transplanted detached signature was not rejected: %v", err)
	}
}

func TestDetachedSignerJournalRefusesSecondValidDraft(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	first := unsignedDescriptor(successor)
	second := first
	second.RetireAt = canonicalTime(successor.RetireAt.Add(time.Minute))
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CreateActivationArtifact(
		first, f.AuthorityPublic, &genesis, nil,
		f.Operators[0].ID, f.Operators[0].Identity,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CreateActivationArtifact(
		second, f.AuthorityPublic, &genesis, nil,
		f.Operators[0].ID, f.Operators[0].Identity,
	); !errors.Is(err, ErrConflictingSignature) {
		t.Fatalf("second valid draft was not stopped by the journal: %v", err)
	}
}

func TestSignatureArtifactDecoderRejectsAmbiguousJSON(t *testing.T) {
	encoded := []byte(`{"version":"nomad-epoch-signature-artifact-v1","version":"nomad-epoch-signature-artifact-v1"}`)
	if _, err := DecodeSignatureArtifact(encoded); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("ambiguous signature artifact was not rejected: %v", err)
	}
}
