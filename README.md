# ebpf-policy

> Distributed DDoS mitigation and traffic rate-limiting system with kernel-level packet filtering and centralized real-time policy management.

**eBPF/XDP** filters packets directly at the network driver level — long before they reach the application layer — while policy decisions are distributed in real time via **NATS** to all running agents. System and traffic metrics are persisted to **TimescaleDB** (or SQLite) and queryable via REST.

---

## Table of Contents

- [Architecture](#architecture)
- [Data Flow](#data-flow)
- [eBPF Maps](#ebpf-maps)
- [Rule Matching](#rule-matching)
- [Environment Tags](#environment-tags)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start (using Make)](#quick-start-using-make)
- [Manual Installation](#manual-installation)
- [Running the System](#running-the-system)
- [REST API](#rest-api)
- [Grafana Dashboard](#grafana-dashboard)
- [Database Schema](#database-schema)
- [Technologies](#technologies)

---

## Architecture

```
┌──────────────────────────────┐
│         Policy Server        │   Control Plane
│   REST API :8080             │
│   SQLite / TimescaleDB       │
│   Policy publishing          │
│   Metrics collection         │
└──────────────┬───────────────┘
               │
           NATS pub/sub
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────┐
│   Agent 1   │  │   Agent N   │   Edge Nodes
│   (eBPF)    │  │   (eBPF)    │
└─────────────┘  └─────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **Server** | Manages policies via REST API, persists rules and metrics to SQLite or TimescaleDB, and distributes changes via NATS |
| **Agent** | Runs on each node, loads the eBPF program into the kernel, reports per-IP traffic stats and system metrics |
| **eBPF/XDP** | Kernel-space C program that filters packets at the network interface with microsecond latency |
| **NATS** | Message broker for policy distribution and metrics aggregation across all agents |

### NATS Topics

| Topic | Direction | Purpose |
|-------|-----------|---------|
| `policy.update` | Server → Agents | New or updated global rule |
| `policy.update.<tag>` | Server → Agents | New or updated rule for a specific environment |
| `policy.delete` | Server → Agents | Deleted global rule |
| `policy.delete.<tag>` | Server → Agents | Deleted rule for a specific environment |
| `metrics.report` | Agents → Server | Per-IP traffic stats (every 10 s) |
| `system.metrics` | Agents → Server | System performance metrics (every 30 s) |

---

## Data Flow

**Packet filtering (eBPF/XDP, kernel-space):**

```
Incoming network packet
  → Parse Ethernet → IPv4 header
  → Check block_list
      → Match and not expired:  XDP_DROP
      → Expired block:          removed automatically, XDP_PASS
  → Token bucket check (rate limiting)
      → No tokens left:         XDP_DROP
      → Tokens available:       counter incremented, token deducted, XDP_PASS
  → Increment request_count[src_ip]
  → Update latency stats
  → XDP_PASS
```

**Policy update (end-to-end):**

```
PUT /api/rules/:id
  → Validated and persisted to DB
  → Change published on NATS "policy.update[.<tag>]"
  → Matching agents receive message and update rule cache
  → Next packet evaluation applies the new rule
```

**Traffic metrics loop (per agent, every 10 s):**

```
  → Read delta from eBPF maps (request_count, latency_map)
  → Calculate req/s per IP
  → Match against active rules (see Rule Matching)
  → Apply block / rate_limit in kernel
  → Publish MetricsReport to NATS "metrics.report"
  → Server persists to client_stats
```

**System metrics loop (per agent, every 30 s):**

```
  → Collect CPU%, memory%, disk%, network I/O via gopsutil
  → Publish SystemMetricsReport to NATS "system.metrics"
  → Server persists to system_metrics
```

---

## eBPF Maps

The XDP program maintains four LRU hash maps (max 10 000 entries each), keyed by the source IPv4 address as a `uint32`:

| Map | Key | Value | Purpose |
|-----|-----|-------|---------|
| `request_count` | `u32` src IP | `{count, last_seen}` | Cumulative packet counter read by the Go agent every 10 s to calculate req/s |
| `block_list` | `u32` src IP | `u64` ktime expiry (ns) | Hard block — packets are dropped until the expiry timestamp passes |
| `rate_limit_map` | `u32` src IP | `{tokens, last_refill}` | Token-bucket state; the XDP program itself drops packets when tokens reach 0 |
| `latency_map` | `u32` src IP | `{total_ns, count, min_ns, max_ns}` | Per-packet XDP processing latency accumulated for the agent's latency reports |

The XDP program runs in **generic mode** (`XDP_FLAGS_SKB_MODE`) for broad driver compatibility. Native or offload mode can improve performance on supported NICs but requires driver support.

---

## Rule Matching

The agent evaluates each IP against all active rules:

1. Find all rules where the IP's req/s exceeds the rule's `threshold`.
2. **`block` always takes priority over `ratelimit`.**
3. Among rules with the same action, the **highest threshold wins** (most specific rule).

### Token Bucket (kernel-level rate limiting)

| Parameter | Value |
|-----------|-------|
| Refill rate | 100 tokens / second |
| Max capacity (burst) | 200 tokens |

Packets are silently dropped when the token quota is exhausted. Block entries store an expiration timestamp in kernel nanoseconds and are cleaned up automatically.

### Agent Resilience

| Situation | Behavior |
|-----------|----------|
| Server unreachable at startup | Retries 4 times (5 s interval), then falls back to disk cache |
| No disk cache and server down | Starts without rules, keeps retrying |
| Server comes back online | Fetches fresh rules automatically (health check every 15 s) |
| NATS connection drops | Reconnects with exponential backoff (max 5 s) |

Rule cache is saved to `/tmp/ebpf-policy-rules.json` and updated on every successful fetch.

---

## Environment Tags

Rules can be scoped to a specific environment via the `tag` field. Agents filter rules based on their `ENV` variable:

- **Global rule** (empty `tag`): sent to and applied by all agents.
- **Tagged rule** (e.g. `tag: "production"`): sent only to agents where `ENV=production`.

```bash
# Production agent — receives global rules + "production" rules
sudo ENV=production AGENT_ID=prod-agent-1 ./agent

# Staging agent — receives global rules + "staging" rules
sudo ENV=staging AGENT_ID=staging-agent-1 ./agent
```

---

## Requirements

| Dependency | Version |
|------------|---------|
| Ubuntu / Debian Linux | Kernel ≥ 5.9 |
| Go | 1.21+ |
| clang / llvm | Latest stable |
| libbpf-dev | Via apt |
| Linux headers | Matching active kernel |
| Docker + Docker Compose | For infrastructure (NATS + TimescaleDB) |

---

## Installation

Run these steps once on a fresh Ubuntu/Debian machine before starting the system.

### 1. System packages

```bash
sudo apt update && sudo apt install -y \
    clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    make git gcc curl wget
```

> **Note — missing `asm/types.h`:** On some Ubuntu/Debian systems the architecture-specific headers are not symlinked to `/usr/include/asm`, which causes `clang` and `bpf2go` to fail with `fatal error: 'asm/types.h' file not found`. Fix it with:
> ```bash
> sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
> ```

### 2. Go

```bash
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
rm go1.22.4.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

go version
```

### 3. Docker + Docker Compose

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
sudo apt install -y docker-compose-plugin

docker --version
docker compose version
```

> Re-login (or run `newgrp docker`) so the group change takes effect before using `docker` without `sudo`.

### 4. bpf2go

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

### 5. Clone the repository

```bash
git clone https://github.com/ahmadsaflo1/ebpf-policy.git
cd ebpf-policy
```

---

## Quick Start (using Make)

The Makefile wraps all steps. Infrastructure (TimescaleDB + NATS) runs in Docker.

```bash
# 1. Start TimescaleDB and NATS
make start-infra

# 2. Build both binaries (compiles eBPF program + Go code)
make build-server build-agent

# 3. Run the server (uses TimescaleDB by default)
make run-server

#    Override variables to match your environment:
#      INTERFACE   - Network interface to monitor  (default: eth0)
#      AGENT_ID    - Unique name for this agent     (default: unknown)
#      ENV         - Environment tag               (default: "" = receives all rules)
#      SERVER_URL  - Policy server address         (default: http://localhost:8080)
#      NATS_URL    - NATS broker address           (default: nats://localhost:4222)
make run-agent INTERFACE=<iface> AGENT_ID=<name> ENV=<tag> SERVER_URL=http://<server-ip>:8080 NATS_URL=nats://<server-ip>:4222
```

Other useful targets:

```bash
make status        # Show running infrastructure containers
make logs-db       # Stream TimescaleDB logs
make logs-nats     # Stream NATS logs
make stop-infra    # Stop infrastructure containers
make clean         # Remove build artifacts
make help          # List all targets
```

---

## Manual Installation

### 1. Start infrastructure

```bash
make start-infra
```

### 2. Compile the eBPF program

```bash
cd ebpf && make && cd ..
```

### 3. Generate Go bindings

```bash
cd internal/agent/ebpf
bpf2go -go-package ebpf Policy ../../../ebpf/policy.c
cd ../../..
```

| Generated file | Description |
|----------------|-------------|
| `policy_bpfel.go` | Go bindings for little-endian (x86-64) |
| `policy_bpfeb.go` | Go bindings for big-endian |
| `policy_bpfel.o` | Compiled eBPF bytecode for little-endian |
| `policy_bpfeb.o` | Compiled eBPF bytecode for big-endian |

### 4. Build binaries

```bash
go build -o server ./cmd/server/
go build -o agent ./cmd/agent/
```

---

## Running the System

### Server

```bash
./server
```

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `NATS_URL` | `nats://localhost:4222` | NATS broker address |
| `USE_TIMESCALE` | *(unset = SQLite)* | Set to any value to use TimescaleDB |
| `POSTGRES_HOST` | `localhost` | TimescaleDB host |
| `POSTGRES_PORT` | `5432` | TimescaleDB port |
| `POSTGRES_USER` | `ebpf_user` | Database user |
| `POSTGRES_PASSWORD` | `ebpf_secret_password` | Database password |
| `POSTGRES_DB` | `policy_metrics` | Database name |

### Agent

Requires root privileges to attach the XDP program to the network interface.

```bash
sudo INTERFACE=<interface> \
     AGENT_ID=<agent-name> \
     SERVER_URL=http://<server-ip>:8080 \
     NATS_URL=nats://<server-ip>:4222 \
     ENV=<environment> \
     ./agent
```

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `INTERFACE` | `eth0` | Network interface to monitor (e.g. `ens5`) |
| `AGENT_ID` | `agent-001` | Unique identifier for this agent instance |
| `SERVER_URL` | `http://<server-ip>:8080` | URL of the policy server |
| `NATS_URL` | `nats://<server-ip>:4222` | NATS broker address |
| `ENV` | *(empty — global)* | Environment tag for rule filtering |

---

## REST API

Base URL: `http://<server>:8080`

### Policy Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Server health check |
| `GET` | `/api/rules` | List all rules (optional `?env=<tag>`) |
| `POST` | `/api/rules` | Create a new rule |
| `GET` | `/api/rules/:id` | Get a specific rule |
| `PUT` | `/api/rules/:id` | Update a rule |
| `DELETE` | `/api/rules/:id` | Delete a rule |

### Traffic Metrics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/metrics/search` | Search per-IP stats (`?ip=`, `?agent=`, `?limit=`, `?offset=`) |
| `GET` | `/api/metrics/aggregated` | Aggregated stats for an IP (`?ip=<required>`, `?timerange=1h`) |
| `GET` | `/api/metrics/top` | Top N clients (`?limit=10`, `?timerange=1h`, `?order_by=req_per_sec\|blocked`) |

### System Metrics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/system/metrics` | Recent system metrics (`?agent=`, `?timerange=1h`, `?limit=100`) |
| `GET` | `/api/system/metrics/aggregated` | Aggregated system metrics per agent (`?agent=<required>`, `?timerange=1h`) |

### Example: Create a global block rule

```bash
curl -X POST http://<server-ip>:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block >500 req/s",
    "threshold": 500,
    "action": "block",
    "duration": 60
  }'
```

### Example: Create an environment-specific rate-limit rule

```bash
curl -X POST http://<server-ip>:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Rate-limit production at >200 req/s",
    "threshold": 200,
    "action": "ratelimit",
    "duration": 30,
    "tag": "production"
  }'
```

### Rule schema

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Descriptive name |
| `threshold` | `int` | Requests per second trigger threshold |
| `action` | `string` | `"block"` or `"ratelimit"` |
| `duration` | `int` | Enforcement duration in seconds |
| `tag` | `string` | *(optional)* Environment tag — empty = global |

---

## Grafana Dashboard

Grafana ingår i Docker Compose-stacken och laddas automatiskt med en färdig dashboard.

### Starta

```bash
docker compose up -d
```

### Öppna dashboarden

Grafana körs på samma maskin som servern. Ersätt `<server-ip>` med serverns IP-adress:

```
http://<server-ip>:3000
```

Logga in med användare `admin` och lösenord `admin`, klicka sedan på **Dashboards → Browse** och välj **eBPF Policy Overview**.

> Om du kör allt lokalt kan du använda `http://localhost:3000`.

Dashboarden laddas automatiskt via provisioning från `grafana/dashboards/ebpf-policy-overview.json`. Inget manuellt steg krävs.

### Felsökning

Om dashboarden inte syns:

```bash
# Kontrollera att containrarna kör
docker compose ps

# Se loggar
docker compose logs grafana

# Starta om Grafana
docker compose restart grafana
```

Om containrarna inte startar alls:

```bash
docker compose down -v
docker compose up -d
```

---

## Database Schema

The database is created automatically on server startup. TimescaleDB uses hypertables with 1-day chunk intervals and automatic retention policies (30 days for traffic metrics, 7 days for system metrics).

**`policy_rules`**

```sql
id          INTEGER PRIMARY KEY
name        TEXT
threshold   INTEGER
action      TEXT        -- "block" or "ratelimit"
duration    INTEGER     -- seconds
tag         TEXT        -- empty = global rule
created_at  DATETIME
```

**`client_stats`** — per-IP traffic metrics from agents

```sql
id             INTEGER PRIMARY KEY
agent_id       TEXT
ip             TEXT
req_per_sec    INTEGER
blocked        INTEGER     -- 1 = blocked, 0 = allowed
passed         INTEGER     -- packets allowed through
avg_latency_us REAL        -- microseconds
min_latency_us REAL
max_latency_us REAL
recorded_at    DATETIME
```

**`system_metrics`** — agent system performance

```sql
id               INTEGER PRIMARY KEY
agent_id         TEXT
cpu_percent      REAL
memory_percent   REAL
memory_used_mb   INTEGER
memory_total_mb  INTEGER
disk_used_gb     INTEGER
disk_total_gb    INTEGER
disk_percent     REAL
net_bytes_sent   INTEGER
net_bytes_recv   INTEGER
recorded_at      DATETIME
```

---

## Technologies

| Technology | Usage |
|------------|-------|
| [cilium/ebpf](https://github.com/cilium/ebpf) | Loads and manages eBPF programs from Go |
| [NATS](https://nats.io) | Distributed pub/sub messaging (JetStream) |
| [Gin](https://github.com/gin-gonic/gin) | HTTP framework for the REST API |
| [TimescaleDB](https://www.timescale.com) | Time-series PostgreSQL for metrics (default) |
| [SQLite](https://sqlite.org) | Lightweight fallback database |
| [gopsutil](https://github.com/shirou/gopsutil) | System metrics collection (CPU, memory, disk, network) |
| eBPF/XDP | Kernel-level packet filtering with minimal overhead |
