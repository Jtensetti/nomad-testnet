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
	descriptorPath := flag.String("descriptor", "", "signed batch descriptor")
	sharePath := flag.String("share", "", "operator threshold share")
	cachePath := flag.String("cache", "", "operator raw cache")
	outputPath := flag.String("out", "", "public partial-decryption directory")
	interval := flag.Duration("interval", time.Second, "fixed local cache scan interval")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath, "--descriptor": *descriptorPath,
		"--share": *sharePath, "--cache": *cachePath, "--out": *outputPath,
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
	service := share.Service{Cache: cache, Descriptor: descriptor, Secret: secret, OutputDir: *outputPath, Interval: *interval}
	if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
