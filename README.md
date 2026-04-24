# ebpf-policy

> Distributed DDoS mitigation and traffic rate-limiting system with kernel-level packet filtering and centralized real-time policy management.

**eBPF/XDP** filters packets directly at the network driver level — long before they reach the application layer — while policy decisions are distributed in real time via **NATS** to all running agents. System and traffic metrics are persisted to **TimescaleDB** (or SQLite) and queryable via REST.

---

## Table of Contents

- [Architecture](#architecture)
- [Data Flow](#data-flow)
- [Rule Matching](#rule-matching)
- [Environment Tags](#environment-tags)
- [Requirements](#requirements)
- [Quick Start (Docker Compose)](#quick-start-docker-compose)
- [Manual Installation](#manual-installation)
- [Running the System](#running-the-system)
- [REST API](#rest-api)
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

## Rule Matching

The agent evaluates each IP against all active rules:

1. Find all rules where the IP's req/s exceeds the rule's `threshold`.
2. **`block` always takes priority over `rate_limit`.**
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

## Quick Start (Docker Compose)

The Makefile wraps all steps. Infrastructure (TimescaleDB + NATS) runs in Docker.

```bash
# 1. Start TimescaleDB and NATS
make start-infra

# 2. Build both binaries (compiles eBPF program + Go code)
make build-server build-agent

# 3. Run the server (uses TimescaleDB by default)
make run-server

# 4. Run the agent (requires root for eBPF)
make run-agent
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

### 1. System dependencies

```bash
sudo apt update && sudo apt install -y \
    clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    make git gcc
```

### 2. bpf2go

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

### 3. Compile the eBPF program

```bash
cd ebpf && make && cd ..
```

### 4. Generate Go bindings

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

### 5. Build binaries

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
| `SERVER_URL` | `http://localhost:8080` | URL of the policy server |
| `NATS_URL` | `nats://localhost:4222` | NATS broker address |
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
curl -X POST http://localhost:8080/api/rules \
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
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Rate-limit production at >200 req/s",
    "threshold": 200,
    "action": "rate_limit",
    "duration": 30,
    "tag": "production"
  }'
```

### Rule schema

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Descriptive name |
| `threshold` | `int` | Requests per second trigger threshold |
| `action` | `string` | `"block"` or `"rate_limit"` |
| `duration` | `int` | Enforcement duration in seconds |
| `tag` | `string` | *(optional)* Environment tag — empty = global |

---

## Database Schema

The database is created automatically on server startup. TimescaleDB uses hypertables with 1-day chunk intervals and automatic retention policies (30 days for traffic metrics, 7 days for system metrics).

**`policy_rules`**

```sql
id          INTEGER PRIMARY KEY
name        TEXT
threshold   INTEGER
action      TEXT        -- "block" or "rate_limit"
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
