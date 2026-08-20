package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/batch"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/share"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-share:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	epochDescriptorPath := flag.String("epoch-descriptor", "", "verified epoch descriptor to import into the local chain")
	epochChainPath := flag.String("epoch-chain", "", "persisted verified epoch-chain directory")
	descriptorPath := flag.String("descriptor", "", "signed batch descriptor")
	sharePath := flag.String("share", "", "operator threshold share")
	cachePath := flag.String("cache", "", "operator raw cache")
	outputPath := flag.String("out", "", "public partial-decryption directory")
	listen := flag.String("listen", "", "public partial-proof HTTP listen address")
	interval := flag.Duration("interval", time.Second, "fixed local cache scan interval")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath,
		"--epoch-descriptor": *epochDescriptorPath, "--epoch-chain": *epochChainPath,
		"--descriptor": *descriptorPath, "--share": *sharePath, "--cache": *cachePath,
		"--out": *outputPath, "--listen": *listen,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	network, err := topology.Load(*topologyPath, authority, time.Now().UTC())
	if err != nil {
		return err
	}
	chain, err := epoch.OpenChain(*epochChainPath, network.Document.NetworkID, authority, nil)
	if err != nil {
		return fmt.Errorf("open epoch chain: %w", err)
	}
	epochDescriptor, err := readEpochDescriptor(*epochDescriptorPath)
	if err != nil {
		return err
	}
	imported, err := chain.Append(epochDescriptor)
	if err != nil {
		return fmt.Errorf("import epoch descriptor: %w", err)
	}
	if imported.Epoch != network.Document.Epoch || imported.Topology.Digest != network.Digest {
		return errors.New("epoch descriptor does not authorize the configured topology")
	}
	// Refuse startup unless the exact topology epoch is ACTIVE in the fresh
	// chain. This prevents the weaker topology validity envelope from being
	// mistaken for the descriptor's serving window and catches an emergency
	// successor already persisted by another process.
	guard := epoch.FreshGuard{Chain: chain}
	if err := guard.ServesEpoch(network.Document.Epoch, time.Now().UTC()); err != nil {
		return fmt.Errorf("epoch chain does not authorize threshold service: %w", err)
	}
	descriptor, err := batch.LoadDescriptor(*descriptorPath, authority, network)
	if err != nil {
		return err
	}
	secret, err := batch.LoadShare(*sharePath, descriptor, network)
	if err != nil {
		return err
	}
	cache, err := rawcache.Open(*cachePath, 64)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service := share.Service{
		Cache: cache, Descriptor: descriptor, Secret: secret, OutputDir: *outputPath,
		Interval: *interval, ListenAddress: *listen, Guard: guard,
	}
	if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func readEpochDescriptor(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > epoch.MaximumFileBytes {
		return nil, errors.New("epoch descriptor must be a non-empty bounded regular file")
	}
	return os.ReadFile(path)
}
