# nomad-semantic-basins

Local vector-to-basin experiments for Nomad discovery.

The repository separates **embedding** from **quantization**. A caller supplies a vector representation; `Quantizer` maps it to a 64-bit random-hyperplane signature. Hamming distance between signatures is a lossy similarity hint, not an identity or confidentiality primitive.

## Embedders

- `LexicalHashEmbedder` is a deterministic word/character-ngram hashing baseline. It is lexical, not semantic, and exists mainly for tests and offline development.
- `loopback.HTTPEmbedder` talks to a local embedding service. It accepts only literal loopback IPs over HTTP, disables proxies and rejects redirects. It intentionally does not accept a caller-supplied HTTP client, because that would reopen proxy and redirect escape paths for private query text.
- Both embedders bound private input length and vector dimensions. The loopback adapter also bounds the response before opening it, rejects multiple vectors and disables HTTP keep-alives.

## The embedding service channel

The embedding service is the one component handed a reader's query in the clear. Being on loopback says where the query goes, not who receives it: a process that binds the port first, after a crash or on a shared machine, would otherwise receive every query.

So the channel is sealed under a service key shared by exactly two processes, and there is no unauthenticated mode.

- `loopback.HTTPEmbedder` seals the request to the key and refuses to send anything without one.
- `loopback.Service` is the shim that holds the other copy, unseals the request, calls the model server over loopback and seals the reply. It never reaches the model server with a request it could not open, and every refusal it returns is the same message, so it cannot be used as an oracle.
- `cmd/nomad-embed-service` runs that shim. The key lives in a file that must not be readable by any other account; it is never a flag, where the process table would publish it.

Each request draws a fresh 32-byte salt. Both directions derive their own key from it via HKDF-SHA256 and are sealed with AES-256-GCM, so a request key never opens a response and a reply captured once cannot be replayed onto a later request. Plaintext is padded to a multiple of 256 bytes, because AEAD hides content and not length, and the length of a query is information about the query.

```bash
go run ./cmd/nomad-embed-service -key-file service.key -generate-key
go run ./cmd/nomad-embed-service -key-file service.key -upstream http://127.0.0.1:8080
```

`deploy/nomad-embed-service.service` runs the shim under systemd with `IPAddressDeny=any` and `IPAddressAllow=localhost`, so a compromised shim cannot reach off the host even if it stops confining itself. A test pins the directives, because one deleted line is a hole nothing else reports. The unit has **not been exercised against a running system** in this repository: the directives are checked for presence, not by attempting to escape them.

What *is* exercised is the chain itself. `basin/loopback/egress_test.go` runs the client, the shim and a model server inside a network namespace whose only interface is loopback -- off-host is not blocked there, it is absent -- and the embedding still completes. A packet capture inside that namespace records every datagram the chain produced and requires all of them to name loopback at both ends. The namespace shows nothing *could* leave; the capture shows nothing did. The addresses are parsed rather than substring-matched, because `::1` is a substring of `2001:db8::1` and a check that missed that would pass on exactly the packets it exists to catch.

What this does not claim: the service is trusted with the query by construction, so nothing here defends against a service that holds the key and misuses what it sees. `basin.Attest` covers a related but separate question -- whether the model behind it still behaves as it did when it was attested.

## Quantizer

`Quantizer` derives deterministic standard-normal hyperplanes from a public seed and takes the sign of each projection (SimHash-style random hyperplane LSH). Tests check exact determinism, the expected complement for opposite vectors, and that angularly close vectors are materially closer than orthogonal vectors across many deterministic seeds.

## Privacy caveat

Basin identifiers are metadata, not secrets. Similar inputs are intentionally more likely to have similar signatures. Any network design that exposes basin IDs needs a separate inversion, membership-inference and aggregation-leakage analysis.

```bash
go test -race ./...
go vet ./...
go run ./cmd/basin -text 'example text'
```
