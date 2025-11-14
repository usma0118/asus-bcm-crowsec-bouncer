# ============================
# 1. Build Stage
# ============================
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Preload dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -o /out/router-sync ./cmd/router-sync


# ============================
# 2. Final Runtime Stage
# Base = crowdsecurity/custom-bouncer
# Add tini + OpenSSH client
# ============================
FROM ghcr.io/crowdsecurity/custom-bouncer:latest

# Install tini + openssh-client
USER root
RUN apk update && \
    apk add --no-cache tini openssh-client && \
    mkdir -p /config/.ssh && \
    chown -R 1000:1000 /config

# Copy Go binary
COPY --from=builder /out/router-sync /usr/local/bin/router-sync

# tini = PID1
ENTRYPOINT ["/sbin/tini", "--"]
USER nobody:nobody
# Run the sync daemon
CMD ["/usr/local/bin/router-sync"]

EXPOSE 8081
