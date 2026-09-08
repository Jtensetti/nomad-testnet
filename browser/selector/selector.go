package selector

import (
	"context"
	"errors"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

// Selector performs only local discovery/ranking. This package has no
// dependency on the network planner or selection-firewall repository.
type Selector struct {
	embedder  basin.Embedder
	quantizer basin.Quantizer
}

func New(embedder basin.Embedder, quantizer basin.Quantizer) (*Selector, error) {
	if embedder == nil {
		return nil, errors.New("embedder required")
	}
	return &Selector{embedder: embedder, quantizer: quantizer}, nil
}

func (s *Selector) Search(ctx context.Context, query string, candidates []reconstruct.Candidate) ([]reconstruct.Candidate, error) {
	vector, err := s.embedder.Embed(ctx, query)
	if err != nil {
		return nil, err
	}
	target, err := s.quantizer.Basin(vector)
	if err != nil {
		return nil, err
	}
	return reconstruct.Rank(candidates, target), nil
}
