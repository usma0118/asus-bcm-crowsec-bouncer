📘 CrowdSec Asus Router Sync – Developer Guide

This project provides a Go-based reconciliation daemon that syncs CrowdSec ban decisions to an Asus router using SSH, replacing older shell-based logic.

It integrates cleanly with:

CrowdSec LAPI

Custom Bouncer (ghcr.io/crowdsecurity/custom-bouncer)

Kubernetes / FluxCD

Prometheus ServiceMonitor

Router-side iptables (IPv4 only)

The daemon ensures the router firewall is always aligned with CrowdSec decisions:

Adds new IP bans

Removes expired decisions

Uses a single, efficient SSH session with batching

Full host-key pinning (secure)

Exposes a /healthz endpoint for liveness and monitoring

🏗️ Architecture
CrowdSec LAPI                 Kubernetes / Docker
      │                              │
      └── HTTP (ban decisions) ─────▶│ router-sync (Go)
                                      │    │
                                      │    └── SSH batch (host-key pinned)
                                      │
                                      └── /healthz (Prometheus, K8s)
                                           
Asus Router
    │
    └── iptables chain "CROWDSEC" updated atomically

📦 Repository Layout
crowdsec-asus-sync/
  cmd/router-sync/main.go         # entrypoint
  pkg/config/config.go            # YAML + key resolution
  pkg/crowdsec/client.go          # CrowdSec LAPI client
  pkg/router/ssh_router.go        # SSH batching + known_hosts pinning
  pkg/health/health.go            # /healthz server
  pkg/syncer/syncer.go            # periodic reconciliation loop
  Dockerfile                      # multi-stage + tini + ssh client
  README.md

🚀 Features
✔ Replacement for asus-fw.sh

The router IPC logic is now entirely in Go:

Safe (host-key pinned)

Fast (single SSH batch)

Atomic (no partial updates)

IPv4 only (matching Asus router iptables)

✔ Periodic sync loop

Interval configurable (SYNC_INTERVAL, default 5m)

✔ Full Prometheus support

A /healthz endpoint is exposed at :8081 with:

last sync timestamp

last error

status (ok / degraded)

✔ Tiny, production-grade container

Based on ghcr.io/crowdsecurity/custom-bouncer

Includes Tiny as PID1

Includes OpenSSH client

🧩 Configuration

The daemon reads the same config file used by the CrowdSec custom bouncer:

/crowdsec-custom-bouncer.yaml


Example:

api_url: https://crowdsec-service.namespace:8080
api_key: ${BOUNCER_KEY_ASUS_FW}
insecure_skip_verify: true

Environment Variables
Variable	Required	Description
ROUTER_HOST	yes	IP/hostname of Asus router
ROUTER_PORT	no	SSH port, default 22
ROUTER_USER	no	SSH user, default admin
ROUTER_SSH_KEY_PATH	no	Path to private key, default /config/.ssh/id_rsa
ROUTER_KNOWN_HOSTS_FILE	yes	Path to pinned known_hosts file
SYNC_INTERVAL	no	Sync interval, default 5m
HEALTH_ADDR	no	health server listen address (:8081)
🔐 Host Key Pinning

Your Asus router’s SSH host key must be added to known_hosts:

ssh-keyscan 192.168.1.1 >> router_known_hosts


Mount this file to the container:

- name: router-known-hosts
  secret:
    secretName: router-known-hosts


Set the path:

env:
  - name: ROUTER_KNOWN_HOSTS_FILE
    value: "/config/router_known_hosts"

🛠️ Developer Setup
1. Clone repo
git clone https://github.com/usma0118/asus-bcm-crowsec-bouncer
cd crowdsec-asus-sync

2. Build binary
go build -o router-sync ./cmd/router-sync

3. Run locally
ROUTER_HOST=192.168.1.1 \
ROUTER_KNOWN_HOSTS_FILE=./router_known_hosts \
BOUNCER_CONFIG=./crowdsec-custom-bouncer.yaml \
./router-sync

🐳 Docker Build
docker build -t crowdsec-asus-sync .

.

🧪 Testing Sync Logic

Run a manual sync and use debug logs:

zap-log-level=debug \
router-sync


Test that:

Banned CrowdSec IPs get added to router

Expired decisions get removed

/healthz shows status: ok

🎯 Future Enhancements (Planned)

Prometheus counters (additions, deletions, SSH failures)

ipset instead of iptables (more efficient)

Multi-router support

Scenario-based filtering policies

🙌 Contributing

Fork the repository

Create feature branch

Use zap structured logging

Ensure PRs contain:

Go tests (unit or integration)

Clean commits

Updated README where needed

📄 License

MIT (or add your preferred license)