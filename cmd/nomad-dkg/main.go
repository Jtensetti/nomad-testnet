package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	dkgnet "github.com/Jtensetti/nomad-testnet/live/dkg"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nomad-dkg:", err)
		os.Exit(1)
	}
}

func run() error {
	topologyPath := flag.String("topology", "", "authority-signed topology path")
	authorityPath := flag.String("authority-key", "", "pinned topology authority public key")
	secretPath := flag.String("secrets", "", "this operator's 0600 secret file")
	listen := flag.String("listen", "", "DKG HTTP(S) listen address")
	stateDirectory := flag.String("state", "", "new empty append-only DKG state directory")
	shareOutput := flag.String("share-out", "", "new 0600 threshold-share output path")
	certificateOutput := flag.String("certificate-out", "", "new public DKG certificate output path")
	tlsCertificate := flag.String("tls-certificate", "", "TLS certificate for an HTTPS DKG endpoint")
	tlsPrivateKey := flag.String("tls-private-key", "", "TLS private key for an HTTPS DKG endpoint")
	flag.Parse()
	if flag.NArg() != 0 || *topologyPath == "" || *authorityPath == "" || *secretPath == "" || *listen == "" || *stateDirectory == "" || *shareOutput == "" || *certificateOutput == "" {
		return errors.New("--topology, --authority-key, --secrets, --listen, --state, --share-out and --certificate-out are required")
	}
	authority, err := topology.LoadAuthorityKey(*authorityPath)
	if err != nil {
		return err
	}
	network, err := topology.Load(*topologyPath, authority, time.Now().UTC())
	if err != nil {
		return err
	}
	secrets, err := topology.LoadSecrets(*secretPath, network)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := dkgnet.Run(ctx, network, secrets, dkgnet.RunConfig{
		Listen: *listen, StateDirectory: *stateDirectory, ShareOutput: *shareOutput,
		CertificateOutput: *certificateOutput, TLSCertificate: *tlsCertificate, TLSPrivateKey: *tlsPrivateKey,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		OperatorID       string `json:"operator_id"`
		CommitteeID      string `json:"committee_id"`
		CertificateDigest string `json:"certificate_digest"`
		Qualified        int    `json:"qualified"`
	}{secrets.Operator.ID, result.Certificate.Manifest.Committee.ID, fmt.Sprintf("%x", result.Verified.Digest), len(result.Verified.Transcript.Qualified)})
}
