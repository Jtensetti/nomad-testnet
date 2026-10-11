package topology

import (
	"strings"
	"testing"
)

// The DKG threshold is what makes a compromised minority harmless: t-of-n
// decryption means fewer than t operators learn nothing. Two bounds make that
// mean something, and neither had a test.
//
// A threshold above the operator count names a committee that can never
// decrypt. It arises from governance rather than from a typo: revoking
// operators shrinks membership, and the topology that follows must either
// lower the threshold deliberately or fail, never quietly activate an epoch
// nobody can complete.
//
// A threshold below two makes one operator sufficient, which is the anytrust
// assumption deleted.
//
// Both are enforced in one clause of validateDocument, and deleting that
// clause left the whole suite green.
func TestTheThresholdMustBeReachableAndMoreThanOne(t *testing.T) {
	for name, threshold := range map[string]uint32{
		"one operator is enough":      1,
		"zero":                        0,
		"one more than the committee": 4,
		"far above the committee":     99,
	} {
		document, _ := unattestedDocument(t, "threshold-test", 3)
		document.DKG.Threshold = threshold
		err := ValidateDraft(document)
		if err == nil {
			t.Errorf("a topology with threshold %d over 3 operators was accepted (%s)",
				threshold, name)
			continue
		}
		// The first version of this check used two operators, which trips the
		// three-operator floor first: it was refused, and not for the reason
		// being tested. The error has to name the threshold or this proves
		// nothing about the threshold.
		if !strings.Contains(err.Error(), "threshold") {
			t.Errorf("threshold %d (%s) was refused for %q, which does not mention the "+
				"threshold, so this case is being caught by some other rule",
				threshold, name, err)
		}
	}
}

// The control: the same document with a reachable threshold must be accepted,
// or the cases above would pass because the fixture is invalid for some
// unrelated reason.
func TestAReachableThresholdIsAccepted(t *testing.T) {
	for _, threshold := range []uint32{2, 3} {
		document, _ := unattestedDocument(t, "threshold-test", 3)
		document.DKG.Threshold = threshold
		if err := ValidateDraft(document); err != nil {
			t.Fatalf("a topology with threshold %d over 3 operators was refused: %v",
				threshold, err)
		}
	}
}
