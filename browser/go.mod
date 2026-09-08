module github.com/Jtensetti/nomad-browser

go 1.25.0

require (
	github.com/Jtensetti/nomad-local-reconstruction v0.0.0
	github.com/Jtensetti/nomad-selection-firewall v0.0.0
	github.com/Jtensetti/nomad-semantic-basins v0.0.0
)

replace github.com/Jtensetti/nomad-local-reconstruction => ./components/nomad-local-reconstruction

replace github.com/Jtensetti/nomad-selection-firewall => ./components/nomad-selection-firewall

replace github.com/Jtensetti/nomad-semantic-basins => ./components/nomad-semantic-basins
