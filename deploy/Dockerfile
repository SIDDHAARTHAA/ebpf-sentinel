FROM golang:1.25-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    gcc \
    libbpf-dev \
    llvm \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOCACHE=/tmp/ebpf-sentinel-gocache make build

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/bin/sentinel /usr/local/bin/sentinel

ENV SENTINEL_PROFILE_PATH=/etc/sentinel/profiles/default.yaml

ENTRYPOINT ["/usr/local/bin/sentinel"]
