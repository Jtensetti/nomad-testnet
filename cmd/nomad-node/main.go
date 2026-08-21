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
	"github.com/Jtensetti/nomad-testnet/live/relayipc"
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
	listen := flag.String("listen", "", "stable signed UDP receive address")
	cachePath := flag.String("cache", "", "raw ciphertext cache directory")
	statePath := flag.String("state", "", "persistent sequence state file (coupled mode; shaper owns it in isolated mode)")
	healthPath := flag.String("health", "", "local health JSON path")
	seedPath := flag.String("seed", "", "optional public encrypted seed bundle")
	cacheStreams := flag.Int("cache-streams", 64, "maximum immutable raw-cache streams")
	cacheSweep := flag.Duration("cache-sweep", 30*time.Second, "public cache replication sweep")
	egressMode := flag.String("egress-mode", "coupled", "egress architecture for controlled A/B: coupled or isolated")
	relaySocket := flag.String("relay-socket", "", "absolute Unix datagram socket owned by nomad-shaper in isolated mode")
	flag.Parse()

	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath, "--secrets": *secretsPath,
		"--listen": *listen, "--cache": *cachePath, "--health": *healthPath,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if *egressMode != "coupled" && *egressMode != "isolated" {
		return errors.New("--egress-mode must be coupled or isolated")
	}
	if *egressMode == "coupled" && *statePath == "" {
		return errors.New("--state is required in coupled mode")
	}
	if *egressMode == "isolated" && *relaySocket == "" {
		return errors.New("--relay-socket is required in isolated mode")
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

	config := node.Config{
		Topology: verifiedTopology, Secrets: secrets, ListenAddress: *listen,
		Cache: cache, HealthPath: *healthPath, CacheSweep: *cacheSweep, Seed: seed,
	}
	var relay *relayipc.Client
	if *egressMode == "coupled" {
		config.LegacyCoupledEgress = true
		config.SequencePath = *statePath
	} else {
		relay, err = relayipc.Dial(*relaySocket)
		if err != nil {
			return fmt.Errorf("connect to fixed-rate shaper: %w", err)
		}
		defer relay.Close()
		config.Relay = relay
	}

	liveNode, err := node.New(config)
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
