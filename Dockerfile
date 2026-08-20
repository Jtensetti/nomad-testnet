# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
# Image builds run many services concurrently under BuildKit. Run deterministic
# short tests here, but leave wall-clock traffic-analysis campaigns to the
# dedicated CI privacy job where their noise controls and evidence are valid.
# TestWireTimingIsIndependentOfPrivateActivityUnderStress explicitly skips
# under -short; the unchanged 2% gate is still run by `go test -race ./...` in CI.
RUN CGO_ENABLED=0 go test -short ./live/... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-bootstrap ./cmd/nomad-bootstrap && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-dkg ./cmd/nomad-dkg && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-fixture-publisher ./cmd/nomad-fixture-publisher && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-node ./cmd/nomad-node && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-operator ./cmd/nomad-operator && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-topology ./cmd/nomad-topology && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-share ./cmd/nomad-share && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-partial-fetch ./cmd/nomad-partial-fetch && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nomad-materializer ./cmd/nomad-materializer

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/ /usr/local/bin/
RUN mkdir -p /runtime/public \
    /runtime/operators/operator-a \
    /runtime/operators/operator-b \
    /runtime/operators/operator-c \
    /cache /state /partials /verified /config /operator /authority /dkg \
    /certificate /published /operators/a /operators/b /operators/c && \
    chown -R 65532:65532 /runtime /cache /state /partials /verified /config /operator \
    /authority /dkg /certificate /published /operators
USER 65532:65532
ENTRYPOINT []