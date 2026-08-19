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

	"github.com/Jtensetti/nomad-testnet/live/bundle"
	"github.com/Jtensetti/nomad-testnet/live/node"
	"github.com/Jtensetti/nomad-testnet/live/rawcache"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-node:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	secretsPath := flag.String("secrets", "", "operator secret JSON")
	listen := flag.String("listen", "", "local UDP listen address")
	cachePath := flag.String("cache", "", "raw ciphertext cache directory")
	statePath := flag.String("state", "", "persistent sequence state file")
	healthPath := flag.String("health", "", "local health JSON path")
	seedPath := flag.String("seed", "", "optional public encrypted seed bundle")
	cacheStreams := flag.Int("cache-streams", 64, "maximum immutable raw-cache streams")
	cacheSweep := flag.Duration("cache-sweep", 30*time.Second, "public cache replication sweep")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath, "--secrets": *secretsPath,
		"--listen": *listen, "--cache": *cachePath, "--state": *statePath, "--health": *healthPath,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	verifiedTopology, err := topology.Load(*topologyPath, authority, time.Now().UTC())
	if err != nil {
		return err
	}
	secrets, err := topology.LoadSecrets(*secretsPath, verifiedTopology)
	if err != nil {
		return err
	}
	cache, err := rawcache.Open(*cachePath, *cacheStreams)
	if err != nil {
		return err
	}
	var seed *bundle.Verified
	if *seedPath != "" {
		loaded, err := bundle.Load(*seedPath)
		if err != nil {
			return err
		}
		seed = &loaded
	}
	liveNode, err := node.New(node.Config{
		Topology: verifiedTopology, Secrets: secrets, ListenAddress: *listen,
		Cache: cache, SequencePath: *statePath, HealthPath: *healthPath,
		CacheSweep: *cacheSweep, Seed: seed,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := liveNode.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
