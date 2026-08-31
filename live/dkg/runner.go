package dkgnet

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/topology"
	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

type RunConfig struct {
	Listen            string
	StateDirectory    string
	ShareOutput       string
	CertificateOutput string
	TLSCertificate    string
	TLSPrivateKey     string
}

type RunResult struct {
	Certificate committee.Certificate
	Verified    committee.Verified
	Share       committee.ShareFile
}

func Run(ctx context.Context, network topology.Verified, secrets topology.VerifiedSecrets, config RunConfig) (RunResult, error) {
	if ctx == nil || config.Listen == "" || config.StateDirectory == "" || config.ShareOutput == "" || config.CertificateOutput == "" {
		return RunResult{}, errors.New("complete DKG run configuration is required")
	}
	start, err := time.Parse(time.RFC3339, network.Document.DKG.StartAt)
	if err != nil {
		return RunResult{}, err
	}
	if !time.Now().UTC().Before(start) {
		return RunResult{}, errors.New("refuse to join a DKG session after its signed start time")
	}
	store, err := NewStore(config.StateDirectory, network)
	if err != nil {
		return RunResult{}, err
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	board, err := NewBoard(runContext, network, secrets, store)
	if err != nil {
		return RunResult{}, err
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return RunResult{}, err
	}
	server := &http.Server{
		Handler: board.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	serverErrors := make(chan error, 1)
	endpoint, _ := url.Parse(secrets.Operator.DKGEndpoint)
	go func() {
		var serveErr error
		if endpoint.Scheme == "https" {
			if config.TLSCertificate == "" || config.TLSPrivateKey == "" {
				serveErr = errors.New("HTTPS DKG endpoint requires a TLS certificate and private key")
			} else {
				serveErr = server.ServeTLS(listener, config.TLSCertificate, config.TLSPrivateKey)
			}
		} else {
			serveErr = server.Serve(listener)
		}
		if !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
		}
	}()
	defer func() {
		cancel()
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownContext)
		board.Wait()
	}()

	nonce, err := base64.StdEncoding.Strict().DecodeString(network.Document.DKG.SessionID)
	if err != nil || len(nonce) != 32 {
		return RunResult{}, errors.New("invalid signed DKG nonce")
	}
	identities := make([]mix.DKGPublicIdentity, len(network.Document.Operators))
	for index, operator := range network.Document.Operators {
		encoded, err := base64.StdEncoding.Strict().DecodeString(operator.DKGIdentityKey)
		if err != nil || len(encoded) != len(mix.DKGPublicIdentity{}) {
			return RunResult{}, fmt.Errorf("invalid DKG identity for %s", operator.ID)
		}
		copy(identities[index][:], encoded)
	}
	kyberConfig, err := mix.NewPedersenDKGConfig(secrets.DKG, identities, network.Document.DKG.Threshold, nonce)
	if err != nil {
		return RunResult{}, err
	}
	phaser := newScheduledPhaser(runContext, start, time.Duration(network.Document.DKG.PhaseDurationMillis)*time.Millisecond)
	protocol, err := dkg.NewProtocol(kyberConfig, board, phaser, false)
	if err != nil {
		return RunResult{}, err
	}
	phaser.Start()

	var protocolResult *dkg.Result
	select {
	case outcome := <-protocol.WaitEnd():
		if outcome.Error != nil {
			return RunResult{}, fmt.Errorf("the Pedersen DKG did not complete: %w", outcome.Error)
		}
		protocolResult = outcome.Result
	case err := <-store.Fatal():
		return RunResult{}, err
	case err := <-serverErrors:
		return RunResult{}, err
	case <-ctx.Done():
		return RunResult{}, ctx.Err()
	}
	if protocolResult == nil {
		return RunResult{}, errors.New("the Pedersen DKG completed without a result")
	}
	if len(protocolResult.QUAL) != len(network.Document.Operators) {
		return RunResult{}, errors.New("fail-closed DKG activation requires every configured operator in QUAL")
	}
	for index, member := range protocolResult.QUAL {
		if member.Index != uint32(index) {
			return RunResult{}, errors.New("DKG QUAL does not exactly match ordered topology membership")
		}
	}
	deals, responses, justifications, err := board.TranscriptPackets()
	if err != nil {
		return RunResult{}, err
	}
	committeeID, err := committee.IDForTopology(network)
	if err != nil {
		return RunResult{}, err
	}
	publicCommittee, memberSecret, transcript, err := mix.MaterializePedersenDKG(
		committeeID, network.Document.Epoch, network.Document.DKG.Threshold, nonce,
		identities, deals, responses, justifications, protocolResult,
	)
	if err != nil {
		return RunResult{}, err
	}
	manifest, err := committee.NewManifest(network, publicCommittee, transcript)
	if err != nil {
		return RunResult{}, err
	}
	attestation, err := committee.CreateAttestation(manifest, secrets.Operator, secrets.Identity)
	if err != nil {
		return RunResult{}, err
	}
	vote, err := encodeResultVote(manifest, attestation)
	if err != nil {
		return RunResult{}, err
	}
	board.PushResult(vote)
	resultMessages, err := board.WaitForResults(runContext)
	if err != nil {
		return RunResult{}, err
	}
	manifestDigest, err := committee.ManifestDigest(manifest)
	if err != nil {
		return RunResult{}, err
	}
	attestations := make([]committee.Attestation, len(resultMessages))
	for index, message := range resultMessages {
		sender := network.Document.Operators[message.Envelope.SenderIndex]
		attestations[index], err = decodeResultVote(message.Payload, sender, manifestDigest)
		if err != nil {
			return RunResult{}, err
		}
	}
	certificate, err := committee.Assemble(manifest, attestations, network)
	if err != nil {
		return RunResult{}, err
	}
	verified, err := committee.Verify(certificate, network)
	if err != nil {
		return RunResult{}, err
	}
	share := committee.ShareFromSecret(memberSecret, secrets.Operator, network)
	shareBytes, err := committee.EncodeShare(share)
	if err != nil {
		return RunResult{}, err
	}
	certificateBytes, err := committee.Encode(certificate)
	if err != nil {
		return RunResult{}, err
	}
	if err := requireRealParent(config.ShareOutput); err != nil {
		return RunResult{}, err
	}
	if err := requireRealParent(config.CertificateOutput); err != nil {
		return RunResult{}, err
	}
	if err := writeNew(config.ShareOutput, shareBytes, 0o600); err != nil {
		return RunResult{}, err
	}
	if err := writeNew(config.CertificateOutput, certificateBytes, 0o644); err != nil {
		return RunResult{}, err
	}
	if err := store.Complete(verified.Digest); err != nil {
		return RunResult{}, err
	}
	return RunResult{Certificate: certificate, Verified: verified, Share: share}, nil
}

type scheduledPhaser struct {
	ctx      context.Context
	start    time.Time
	duration time.Duration
	out      chan dkg.Phase
}

func newScheduledPhaser(ctx context.Context, start time.Time, duration time.Duration) *scheduledPhaser {
	return &scheduledPhaser{ctx: ctx, start: start, duration: duration, out: make(chan dkg.Phase, 4)}
}

func (p *scheduledPhaser) NextPhase() chan dkg.Phase {
	return p.out
}

func (p *scheduledPhaser) Start() {
	go func() {
		phases := []dkg.Phase{dkg.DealPhase, dkg.ResponsePhase, dkg.JustifPhase, dkg.FinishPhase}
		for index, phase := range phases {
			when := p.start.Add(time.Duration(index) * p.duration)
			timer := time.NewTimer(time.Until(when))
			select {
			case <-p.ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
			select {
			case p.out <- phase:
			case <-p.ctx.Done():
				return
			}
		}
	}()
}

func requireRealParent(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output parent must be a real directory")
	}
	return nil
}
