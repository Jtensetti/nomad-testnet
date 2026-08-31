package mix

import (
	"strings"
	"testing"
)

// Which refusal a caller sees, when a batch of partials is wrong in two ways
// at once.
//
// verifiedPartialPoints verifies partials in parallel. The results are then
// walked in the original slice order, so the error reported is the one the
// sequential version reported. This pins that: without the ordered walk, a
// batch carrying both an invalid partial and a duplicated member would return
// whichever goroutine happened to finish first, and an error whose identity
// depends on scheduling is a coin toss rather than a check.
func TestTheFirstFaultInSliceOrderIsTheOneReported(t *testing.T) {
	committee, members, err := GenerateDealerCommittee(testCommitteeID(), 13, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := Encrypt(committee.PublicKey, testCells(3))
	if err != nil {
		t.Fatal(err)
	}
	partials := make([]*PartialDecryption, 3)
	for index := range partials {
		partials[index], err = CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			t.Fatal(err)
		}
	}

	tampered := *partials[1]
	tampered.Points = append([][pointSize]byte(nil), partials[1].Points...)
	tampered.Proof = append([]byte(nil), partials[1].Proof...)
	tampered.Points[0][0] ^= 0x80

	// The property under test is WHICH fault is reported, not its wording, so
	// each case says whether the answer must name the duplicate or must not.
	// A tampered point fails at the unmarshal rather than at the proof, and
	// pinning that phrasing would make this a test of an error string.
	for name, testCase := range map[string]struct {
		partials      []*PartialDecryption
		wantDuplicate bool
	}{
		// The tampered partial comes first, so its verification failure is
		// the fault reported even though a duplicate follows it.
		"an invalid partial before a duplicate": {
			partials:      []*PartialDecryption{&tampered, partials[0], partials[0]},
			wantDuplicate: false,
		},
		// The duplicate comes first. Both entries verify, so the fault is the
		// duplicated member, and the tampered partial behind it is never
		// reached.
		"a duplicate before an invalid partial": {
			partials:      []*PartialDecryption{partials[0], partials[0], &tampered},
			wantDuplicate: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Repeated, because a scheduling-dependent answer is right some of
			// the time and this must be right every time.
			for attempt := 0; attempt < 12; attempt++ {
				_, err := ThresholdDecryptColumns(committee, batch, testCase.partials)
				if err == nil {
					t.Fatalf("attempt %d accepted a batch that is wrong in two ways", attempt)
				}
				duplicate := strings.Contains(err.Error(), "duplicate partial-decryption member")
				if duplicate != testCase.wantDuplicate {
					expected := "the invalid partial"
					if testCase.wantDuplicate {
						expected = "the duplicated member"
					}
					t.Fatalf("attempt %d reported %q; the fault in slice order is %s. "+
						"Parallel verification must not change which fault a caller is "+
						"told about", attempt, err, expected)
				}
			}
		})
	}
}
