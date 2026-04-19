# ebpf-policy

> Distributed DDoS mitigation and traffic rate-limiting system with kernel-level packet filtering and centralized real-time policy management.

**eBPF/XDP** filters packets directly at the network driver level — long before they reach the application layer — while policy decisions are distributed in real time via **NATS** to all running agents.

---

## Table of Contents

- [Architecture](#architecture)
- [Data Flow](#data-flow)
- [Rule Matching](#rule-matching)
- [Environment Tags](#environment-tags)
- [Requirements](#requirements)
- [Installation](#installation)
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
│   SQLite database            │
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
| **Server** | Manages policies via REST API, persists rules in SQLite, and distributes changes via NATS |
| **Agent** | Runs on each node, loads the eBPF program into the kernel, and blocks IPs that exceed defined thresholds |
| **eBPF/XDP** | Kernel-space C program that filters packets directly at the network interface level with minimal latency |
| **NATS** | Message broker that distributes policy changes and aggregates metrics from all agents |

### NATS Topics

Rules with a `tag` are only sent to agents with a matching `ENV`. Global rules (no tag) are sent to all agents.

| Topic | Direction | Purpose |
|-------|-----------|---------|
| `policy.update` | Server → Agents | New or updated global rule (no tag) |
| `policy.update.<tag>` | Server → Agents | New or updated rule for a specific environment |
| `policy.delete` | Server → Agents | Deleted global rule |
| `policy.delete.<tag>` | Server → Agents | Deleted rule for a specific environment |
| `metrics.report` | Agents → Server | Per-IP traffic stats, reported every 10 seconds |

---

## Data Flow

**Packet filtering (per agent, eBPF/XDP in kernel):**

```
Incoming network packet
  → XDP program checks block_list
      → Match and not expired:  XDP_DROP  — packet discarded immediately
      → Expired block:          removed from block_list, XDP_PASS
  → Token bucket check (rate limiting)
      → No tokens left:         XDP_DROP
      → Tokens available:       counter incremented, token deducted, XDP_PASS
```

**Policy update (end-to-end):**

```
PUT /api/rules/:id
  → REST handler validates and accepts the request
  → Rule persisted to SQLite
  → Change published on NATS "policy.update[.<tag>]"
  → Matching agents receive the message and update their rule cache
  → Next packet check applies the new rule
```

**Metrics loop (per agent):**

```
Every 10 seconds:
  → Agent reads delta from eBPF map (request_count)
  → Calculates req/s per IP
  → Matches against active rules (see Rule Matching)
  → Applies block/rate_limit in the kernel
  → Publishes MetricsReport to NATS "metrics.report"
  → Server persists stats to client_stats
```

---

## Rule Matching

The agent evaluates each IP against all active rules using the following priority order:

1. Find all rules where the IP's req/s exceeds the rule's `threshold`.
2. **`block` always takes priority over `rate_limit`.**
3. Among rules with the same action, the rule with the **highest threshold** wins (most specific rule takes precedence).

### Token Bucket (kernel-level rate limiting)

The eBPF program implements a per-IP token bucket directly in the `rate_limit_map` BPF map:

| Parameter | Value |
|-----------|-------|
| Refill rate | 100 tokens/second |
| Max capacity (burst) | 200 tokens |

Packets are silently dropped when the token quota is exhausted. Entries in `block_list` store an expiration timestamp in nanoseconds (kernel time) and are cleaned up automatically without explicit deletion.

### Agent Resilience

| Situation | Behavior |
|-----------|----------|
| Server unreachable at startup | Retries 4 times (5 s interval), then falls back to disk cache |
| No disk cache and server down | Starts without rules, keeps retrying |
| Server comes back online | Fetches fresh rules automatically (health check every 15 s) |
| NATS connection drops | Reconnects with exponential backoff (max wait 5 s) |

The rule cache is saved to `/tmp/ebpf-policy-rules.json` and updated on every successful fetch.

---

## Environment Tags

Rules can be scoped to a specific environment via the `tag` field. Agents filter rules based on their `ENV` environment variable:

- **Global rule** (empty `tag`): sent to and applied by all agents.
- **Tagged rule** (e.g. `tag: "production"`): sent only to agents with `ENV=production`.

```bash
# Production agent receives global rules + rules tagged "production"
sudo ENV=production AGENT_ID=prod-agent-1 ./agent

# Staging agent receives global rules + rules tagged "staging"
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
| NATS server | Provided separately |

---

## Installation

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

> Add `export PATH=$PATH:$(go env GOPATH)/bin` to `~/.bashrc` or `~/.profile` to make this permanent.

### 3. Compile the eBPF program

```bash
cd ebpf && make && cd ..
```

Compiles `policy.c` into eBPF bytecode (`policy.o`) using clang.

### 4. Generate Go bindings

```bash
cd internal/agent/ebpf
bpf2go -go-package ebpf Policy ../../../ebpf/policy.c
cd ../../..
```

Generated files:

| File | Description |
|------|-------------|
| `policy_bpfel.go` | Go bindings for little-endian (e.g. x86-64) |
| `policy_bpfeb.go` | Go bindings for big-endian |
| `policy_bpfel.o` | Compiled eBPF bytecode for little-endian |
| `policy_bpfeb.o` | Compiled eBPF bytecode for big-endian |

### 5. Build the binaries

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

The server listens on port `:8080` and connects to NATS at `nats://localhost:4222` by default.

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `NATS_URL` | `nats://localhost:4222` | NATS broker address |

### Agent

The agent requires root privileges to load eBPF programs into the kernel.

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
| `INTERFACE` | `eth0` | Network interface to monitor (e.g. `ens5`, `eth0`) |
| `AGENT_ID` | `agent-001` | Unique identifier for this agent instance |
| `SERVER_URL` | `http://localhost:8080` | URL of the policy server |
| `NATS_URL` | `nats://localhost:4222` | NATS broker address |
| `ENV` | *(empty — global)* | Environment tag for rule filtering (e.g. `production`, `staging`) |

---

## REST API

Base URL: `http://<server>:8080`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Server health status |
| `GET` | `/api/rules` | List all policy rules |
| `POST` | `/api/rules` | Create a new policy rule |
| `GET` | `/api/rules/:id` | Get a specific rule |
| `PUT` | `/api/rules/:id` | Update an existing rule |
| `DELETE` | `/api/rules/:id` | Delete a rule |

### Example: Create a global block rule

```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block >500 requests/s",
    "threshold": 500,
    "action": "block",
    "duration": 60
  }'
```

### Example: Create an environment-specific rate limit

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

**Schema fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Descriptive name for the rule |
| `threshold` | `int` | Threshold in requests per second |
| `action` | `string` | `"block"` or `"rate_limit"` |
| `duration` | `int` | Block duration in seconds |
| `tag` | `string` | *(optional)* Environment tag — leave empty for a global rule |

---

## Database Schema

The SQLite database (`policy.db`) is created automatically in the working directory on startup.

**`policy_rules`** — Policy rules:

```sql
id          INTEGER PRIMARY KEY
name        TEXT
threshold   INTEGER
action      TEXT        -- "block" or "rate_limit"
duration    INTEGER     -- seconds
tag         TEXT        -- environment tag, empty = global
created_at  DATETIME
```

**`client_stats`** — Traffic statistics from agents:

```sql
id           INTEGER PRIMARY KEY
agent_id     TEXT
ip           TEXT
req_per_sec  REAL
blocked      INTEGER    -- 1 = blocked, 0 = not blocked
passed       INTEGER    -- total packets allowed through
recorded_at  DATETIME
```

---

## Technologies

| Technology | Usage |
|------------|-------|
| [cilium/ebpf](https://github.com/cilium/ebpf) | Loads and manages eBPF programs from Go |
| [NATS](https://nats.io) | Distributed pub/sub messaging |
| [Gin](https://github.com/gin-gonic/gin) | HTTP framework for the REST API |
| [SQLite](https://sqlite.org) | Local relational database for rules and statistics |
| eBPF/XDP | Kernel-level packet filtering with minimal overhead |
