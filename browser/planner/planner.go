package planner

import "github.com/Jtensetti/nomad-selection-firewall/firewall"

// Planner owns only public emission-planning state. This package has no
// dependency on semantic basins or local reconstruction.
type Planner struct {
	config firewall.NetworkConfig
}

func New(config firewall.NetworkConfig) (*Planner, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Planner{config: config}, nil
}

func (p *Planner) Plan(epoch uint64) ([]firewall.Emission, error) {
	return firewall.Plan(p.config, epoch)
}
