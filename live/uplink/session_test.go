package uplink

import (
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

func testSession(t *testing.T) *Session {
	t.Helper()
	public, _, err := mix.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession([]byte("uplink-test-shared-secret"), public, Context{
		NetworkID: "nomad-test", Epoch: 1,
		TopologyDigest: [32]byte{1, 2, 3}, EntryOperator: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}
