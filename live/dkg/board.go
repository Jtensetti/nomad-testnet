package dkgnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"

	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type Board struct {
	ctx       context.Context
	network   topology.Verified
	secrets   topology.VerifiedSecrets
	store     *Store
	client    *http.Client
	deals     chan dkg.DealBundle
	responses chan dkg.ResponseBundle
	justifs   chan dkg.JustificationBundle
	notify    chan struct{}
	wg        sync.WaitGroup
}

func NewBoard(ctx context.Context, network topology.Verified, secrets topology.VerifiedSecrets, store *Store) (*Board, error) {
	if ctx == nil || store == nil {
		return nil, errors.New("DKG board requires context and store")
	}
	if secrets.Operator.ID == "" {
		return nil, errors.New("verified operator secrets are required")
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        len(network.Document.Operators) * 2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	capacity := len(network.Document.Operators) * 2
	return &Board{
		ctx: ctx, network: network, secrets: secrets, store: store, client: client,
		deals: make(chan dkg.DealBundle, capacity), responses: make(chan dkg.ResponseBundle, capacity),
		justifs: make(chan dkg.JustificationBundle, capacity), notify: make(chan struct{}, 1),
	}, nil
}

func (b *Board) PushDeals(packet *dkg.DealBundle) {
	b.pushPacket(packet)
}

func (b *Board) IncomingDeal() <-chan dkg.DealBundle {
	return b.deals
}

func (b *Board) PushResponses(packet *dkg.ResponseBundle) {
	b.pushPacket(packet)
}

func (b *Board) IncomingResponse() <-chan dkg.ResponseBundle {
	return b.responses
}

func (b *Board) PushJustifications(packet *dkg.JustificationBundle) {
	b.pushPacket(packet)
}

func (b *Board) IncomingJustification() <-chan dkg.JustificationBundle {
	return b.justifs
}

func (b *Board) pushPacket(packet dkg.Packet) {
	phase, sender, payload, err := EncodePacket(packet)
	if err != nil || sender != uint32(b.secrets.Operator.Index) {
		if err == nil {
			err = errors.New("DKG protocol attempted to send for another operator")
		}
		b.store.fail(err)
		return
	}
	b.pushPayload(phase, payload)
}

func (b *Board) PushResult(payload []byte) {
	b.pushPayload(ResultPhase, payload)
}

func (b *Board) pushPayload(phase Phase, payload []byte) {
	envelope, err := NewEnvelope(b.network, b.secrets.Operator, b.secrets.Identity, phase, payload)
	if err != nil {
		b.store.fail(err)
		return
	}
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		b.store.fail(err)
		return
	}
	if err := b.deliver(encoded); err != nil {
		b.store.fail(err)
		return
	}
	for _, peer := range b.network.Document.Operators {
		if peer.Index == b.secrets.Operator.Index {
			continue
		}
		peer := peer
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			if err := b.sendUntilDeadline(peer, phase, encoded); err != nil {
				b.store.fail(err)
			}
		}()
	}
}

func (b *Board) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/v1/dkg/message", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if request.Header.Get("Content-Type") != "application/json" {
			http.Error(writer, "content type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, MaximumEnvelopeSize+1))
		if err != nil || len(body) > MaximumEnvelopeSize {
			http.Error(writer, "invalid envelope body", http.StatusRequestEntityTooLarge)
			return
		}
		if err := b.deliver(body); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrEquivocation) {
				status = http.StatusConflict
			}
			http.Error(writer, "rejected DKG envelope", status)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func (b *Board) deliver(encoded []byte) error {
	envelope, payload, fresh, err := b.store.Accept(encoded)
	if err != nil || !fresh {
		return err
	}
	if envelope.Phase == ResultPhase {
		b.signal()
		return nil
	}
	packet, err := DecodePacket(envelope.Phase, payload)
	if err != nil {
		return err
	}
	switch value := packet.(type) {
	case *dkg.DealBundle:
		select {
		case b.deals <- *value:
		default:
			return errors.New("DKG deal channel capacity exhausted")
		}
	case *dkg.ResponseBundle:
		select {
		case b.responses <- *value:
		default:
			return errors.New("DKG response channel capacity exhausted")
		}
	case *dkg.JustificationBundle:
		select {
		case b.justifs <- *value:
		default:
			return errors.New("DKG justification channel capacity exhausted")
		}
	default:
		return errors.New("unexpected DKG packet type")
	}
	b.signal()
	return nil
}

func (b *Board) sendUntilDeadline(peer topology.Operator, phase Phase, encoded []byte) error {
	deadline, err := b.phaseDeadline(phase)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(peer.DKGEndpoint, "/") + "/v1/dkg/message"
	for {
		if !time.Now().UTC().Before(deadline) {
			return fmt.Errorf("DKG %s delivery to %s missed the signed phase deadline", phase, peer.ID)
		}
		requestContext, cancel := context.WithDeadline(b.ctx, deadline)
		request, requestErr := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, bytes.NewReader(encoded))
		if requestErr == nil {
			request.Header.Set("Content-Type", "application/json")
			response, responseErr := b.client.Do(request)
			if responseErr == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
				_ = response.Body.Close()
				if response.StatusCode == http.StatusNoContent {
					cancel()
					return nil
				}
				if response.StatusCode == http.StatusConflict {
					cancel()
					return fmt.Errorf("peer %s reported DKG equivocation", peer.ID)
				}
			}
		}
		cancel()
		select {
		case <-b.ctx.Done():
			return b.ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (b *Board) phaseDeadline(phase Phase) (time.Time, error) {
	start, err := time.Parse(time.RFC3339, b.network.Document.DKG.StartAt)
	if err != nil {
		return time.Time{}, err
	}
	duration := time.Duration(b.network.Document.DKG.PhaseDurationMillis) * time.Millisecond
	multiplier := 0
	switch phase {
	case DealPhase:
		multiplier = 1
	case ResponsePhase:
		multiplier = 2
	case JustificationPhase:
		multiplier = 3
	case ResultPhase:
		multiplier = 4
	default:
		return time.Time{}, errors.New("unknown DKG phase")
	}
	return start.Add(time.Duration(multiplier) * duration), nil
}

func (b *Board) WaitForResults(ctx context.Context) ([]storedMessage, error) {
	deadline, err := b.phaseDeadline(ResultPhase)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		messages := b.store.PhaseMessages(ResultPhase)
		if len(messages) == len(b.network.Document.Operators) {
			sort.Slice(messages, func(i, j int) bool { return messages[i].Envelope.SenderIndex < messages[j].Envelope.SenderIndex })
			return messages, nil
		}
		select {
		case err := <-b.store.Fatal():
			return nil, err
		case <-b.notify:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("DKG result phase received %d/%d attestations", len(messages), len(b.network.Document.Operators))
		}
	}
}

func (b *Board) TranscriptPackets() ([]*dkg.DealBundle, []*dkg.ResponseBundle, []*dkg.JustificationBundle, error) {
	var deals []*dkg.DealBundle
	var responses []*dkg.ResponseBundle
	var justifications []*dkg.JustificationBundle
	for _, phase := range []Phase{DealPhase, ResponsePhase, JustificationPhase} {
		for _, message := range b.store.PhaseMessages(phase) {
			packet, err := DecodePacket(phase, message.Payload)
			if err != nil {
				return nil, nil, nil, err
			}
			switch value := packet.(type) {
			case *dkg.DealBundle:
				deals = append(deals, value)
			case *dkg.ResponseBundle:
				responses = append(responses, value)
			case *dkg.JustificationBundle:
				justifications = append(justifications, value)
			}
		}
	}
	sort.Slice(deals, func(i, j int) bool { return deals[i].Index() < deals[j].Index() })
	sort.Slice(responses, func(i, j int) bool { return responses[i].Index() < responses[j].Index() })
	sort.Slice(justifications, func(i, j int) bool { return justifications[i].Index() < justifications[j].Index() })
	return deals, responses, justifications, nil
}

func (b *Board) Wait() {
	b.wg.Wait()
	b.client.CloseIdleConnections()
}

func (b *Board) signal() {
	select {
	case b.notify <- struct{}{}:
	default:
	}
}
