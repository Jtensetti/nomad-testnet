package testnet

import (
	"context"
	"testing"
)

func TestEndToEndResearchStack(t *testing.T) {
	content := []byte("A signed Nomad object about Iranian military systems, reconstructed only from coded symbols.")
	r, err := Run(context.Background(), content, "Iran military weapons systems geopolitics", "weapons systems in Iran military")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Reconstructed {
		t.Fatal("object was not reconstructed")
	}
	if !r.ReaderTraceIdentical {
		t.Fatal("private selection changed observable trace")
	}
	if r.MixedBatch < 64 {
		t.Fatalf("batch too small: %d", r.MixedBatch)
	}
	if r.ConstantBytesPerEpoch != 16*1200 {
		t.Fatalf("unexpected visible epoch size: %d", r.ConstantBytesPerEpoch)
	}
}

func TestReaderWorldsHaveSameTrace(t *testing.T) {
	for i := 0; i < 100; i++ {
		r, err := Run(context.Background(), []byte("test content for repeated non-interference test"), "science technology", "private query")
		if err != nil {
			t.Fatal(err)
		}
		if !r.ReaderTraceIdentical {
			t.Fatalf("run %d leaked activity", i)
		}
	}
}
