package testnet

import "github.com/Jtensetti/nomad-anytrust-mix-sim/mix"

func deriveDKGPublicBytes(private mix.DKGPrivateIdentity) ([]byte, error) {
	public, err := mix.DKGPublicFromPrivate(private)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), public[:]...), nil
}
