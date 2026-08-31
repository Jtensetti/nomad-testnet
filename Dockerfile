# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
# The image is built from code that passes its own tests, and -short is what
# keeps that affordable. The heavy campaigns -- the timing measurements, the
# unlinkability experiments, the cross-process boundary run -- already gate
# this image: live-compose declares `needs: unit`, so `go test -race ./...`
# has passed on this exact commit before the build starts. Running them a
# second time here, without the race detector, adds minutes and finds nothing
# the first run did not.
#
# What -short does NOT skip is the bulk of the suite, which is the point: an
# operator building this image outside CI still gets the guard.
RUN CGO_ENABLED=0 go test -short ./live/... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ \
        ./cmd/nomad-bootstrap \
        ./cmd/nomad-dkg \
        ./cmd/nomad-fixture-publisher \
        ./cmd/nomad-node \
        ./cmd/nomad-operator \
        ./cmd/nomad-topology \
        ./cmd/nomad-share \
        ./cmd/nomad-partial-fetch \
        ./cmd/nomad-materializer

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
