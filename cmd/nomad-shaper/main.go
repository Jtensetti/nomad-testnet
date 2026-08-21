package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/shaper"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-shaper:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "signed public topology JSON")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	secretsPath := flag.String("secrets", "", "operator secret JSON")
	bind := flag.String("bind", ":0", "dedicated local UDP egress bind address")
	workSocket := flag.String("work-socket", "", "absolute Unix datagram socket receiving relay work")
	statePath := flag.String("state", "", "persistent shaper sequence state file")
	statsPath := flag.String("stats-out", "", "optional final local shaper stats JSON")
	flag.Parse()
	for name, value := range map[string]string{
		"--topology": *topologyPath, "--authority-key": *authorityPath,
		"--secrets": *secretsPath, "--bind": *bind,
		"--work-socket": *workSocket, "--state": *statePath,
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
	secrets, err := topology.LoadSecrets(*secretsPath, network)
	if err != nil {
		return err
	}
	worker, err := shaper.New(shaper.Config{
		Topology: network, Secrets: secrets, BindAddress: *bind,
		WorkSocket: *workSocket, SequencePath: *statePath,
	})
	if err != nil {
		return err
	}
	defer worker.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runErr := worker.Run(ctx)
	if *statsPath != "" {
		if err := writeFinalStats(*statsPath, worker.Snapshot()); err != nil && runErr == nil {
			runErr = err
		}
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

func writeFinalStats(path string, stats shaper.Stats) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("stats output must be an absolute path")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(parent, ".shaper-stats-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
