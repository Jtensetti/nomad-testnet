package selector

import (
	"context"
	"testing"

	"github.com/Jtensetti/nomad-local-reconstruction/reconstruct"
	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

func TestSearchRanksAlreadyLocalCandidates(t *testing.T) {
	q := basin.Quantizer{}
	e := basin.LexicalHashEmbedder{Dims: 256}
	v, err := e.Embed(context.Background(), "local query")
	if err != nil {
		t.Fatal(err)
	}
	target, err := q.Basin(v)
	if err != nil {
		t.Fatal(err)
	}

	s, err := New(e, q)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []reconstruct.Candidate{
		{Basin: ^target, Score: 1},
		{Basin: target, Score: 0},
	}
	ranked, err := s.Search(context.Background(), "local query", candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 2 || ranked[0].Basin != target {
		t.Fatalf("unexpected ranking: %#v", ranked)
	}
}
