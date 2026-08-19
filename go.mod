module github.com/Jtensetti/nomad-testnet

go 1.25.0

require (
	github.com/Jtensetti/nomad-anytrust-mix-sim v0.0.0
	github.com/Jtensetti/nomad-constant-rate-fabric v0.0.0
	github.com/Jtensetti/nomad-local-reconstruction v0.0.0
	github.com/Jtensetti/nomad-rlnc v0.0.0
	github.com/Jtensetti/nomad-selection-firewall v0.0.0
	github.com/Jtensetti/nomad-semantic-basins v0.0.0
)

replace github.com/Jtensetti/nomad-anytrust-mix-sim => ./components/nomad-anytrust-mix-sim

replace github.com/Jtensetti/nomad-constant-rate-fabric => ./components/nomad-constant-rate-fabric

replace github.com/Jtensetti/nomad-local-reconstruction => ./components/nomad-local-reconstruction

replace github.com/Jtensetti/nomad-rlnc => ./components/nomad-rlnc

replace github.com/Jtensetti/nomad-selection-firewall => ./components/nomad-selection-firewall

replace github.com/Jtensetti/nomad-semantic-basins => ./components/nomad-semantic-basins
