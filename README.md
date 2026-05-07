# ebpf-policy

> Distributed DDoS mitigation and traffic rate-limiting system with kernel-level packet filtering and centralized real-time policy management.

**eBPF/XDP** filters packets directly at the network driver level — long before they reach the application layer — while policy decisions are distributed in real time via **NATS** to all running agents. System and traffic metrics are persisted to **TimescaleDB** and queryable via REST or the built-in web UI.

---

## Table of Contents

- [Architecture](#architecture)
- [Data Flow](#data-flow)
- [eBPF Maps](#ebpf-maps)
- [Rule Matching](#rule-matching)
- [Environment Tags](#environment-tags)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick Start (using Make)](#quick-start-using-make)
- [Manual Build](#manual-build)
- [Running the System](#running-the-system)
- [Web UI](#web-ui)
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
│   TimescaleDB                │
│   Policy publishing          │
│   Metrics collection         │
└──────────────┬───────────────┘
               │
           NATS pub/sub
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────┐
│  Webserver  │  │  Webserver  │   Edge Nodes
│  + Agent    │  │  + Agent    │
│  UI :4040   │  │  UI :4040   │
│  (eBPF)     │  │  (eBPF)     │
└─────────────┘  └─────────────┘
```

### Binaries

| Binary | Description |
|--------|-------------|
| **`policy-server`** | Central control plane — manages rules via REST API, persists data to TimescaleDB, distributes changes via NATS |
| **`webserver`** | Serves the web UI on port 4040 and runs the embedded eBPF/XDP agent — configured via `server.conf` |

### Components

| Component | Description |
|-----------|-------------|
| **Policy Server** | Stores rules, collects metrics, pushes updates to agents via NATS |
| **Agent** | Embedded in the webserver binary — loads the eBPF program, enforces rules, reports metrics |
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
  → Collect CPU% from /proc/stat
  → Collect memory% from /proc/meminfo
  → Collect disk usage via syscall.Statfs
  → Collect network I/O delta from /proc/net/dev
  → Publish SystemMetricsReport to NATS "system.metrics"
  → Server persists to system_metrics
```

---

## eBPF Maps

The XDP program maintains four LRU hash maps (max 10 000 entries each), keyed by the source IPv4 address as a `uint32`:

| Map | Key | Value | Purpose |
|-----|-----|-------|---------|
| `request_count` | `u32` src IP | `{count, last_seen}` | Cumulative packet counter read by the agent every 10 s to calculate req/s |
| `block_list` | `u32` src IP | `u64` ktime expiry (ns) | Hard block — packets are dropped until the expiry timestamp passes |
| `rate_limit_map` | `u32` src IP | `{tokens, last_refill}` | Token-bucket state; the XDP program itself drops packets when tokens reach 0 |
| `latency_map` | `u32` src IP | `{total_ns, count, min_ns, max_ns}` | Per-packet XDP processing latency accumulated for the agent's latency reports |

The XDP program runs in **generic mode** (`XDP_FLAGS_SKB_MODE`) for broad driver compatibility. Native or offload mode can improve performance on supported NICs but requires driver support.

---

## Rule Matching

Rule matching happens at two layers: the **XDP kernel program** filters every packet, and the **Go agent** evaluates traffic statistics every 10 seconds to decide which enforcement actions to apply.

### XDP Packet Pipeline (kernel-space, per packet)

Every inbound packet passes through these steps in order:

```
Incoming packet
  → Non-IPv4?                          XDP_PASS (not tracked)
  → Non-TCP/UDP?                       XDP_PASS (ICMP, IGMP, etc. pass through)
  → Destination port not in protected_ports?  XDP_PASS (unmonitored ports pass through)
  → src IP in block_list and not expired?     XDP_DROP
  → Increment request_count[src_ip]
  → Token bucket exhausted?            XDP_DROP
  → Record XDP latency
  → XDP_PASS
```

Only traffic to ports registered in `protected_ports` is counted and subject to enforcement. All other ports pass through without any tracking.

### Agent Evaluation Loop (user-space, every 10 s)

Every 10 seconds the agent reads the eBPF `request_count` map, computes `req/s = delta / 10` per IP, and calls `store.Match(reqPerSec)` to find the winning rule:

1. Collect all rules where `reqPerSec > rule.Threshold`.
2. **`block` always takes priority over `ratelimit`.**
3. Among rules with the same action, the **highest threshold wins** (most specific rule).
4. Returns no match if no rule's threshold is exceeded — existing rate limits are removed.

**Block enforcement:**

| Situation | Behavior |
|-----------|----------|
| New IP exceeds block threshold | `BlockIP` called — expiry timestamp written to `block_list` kernel map |
| Still blocked and still high | Block extended for another `duration` seconds |
| Block just expired but still high | Re-blocked immediately |
| Block just expired and traffic normal | Unblocked — no action |

**Rate-limit enforcement:**

| Situation | Behavior |
|-----------|----------|
| IP exceeds rate-limit threshold | `SetRateLimit` called — writes `rule.Threshold` req/s to `rate_limit_config_map` |
| Rate already set to same value | No kernel update (idempotent) |
| Traffic drops below threshold | `RemoveRateLimit` called — clears both config and token-bucket state |

### Token Bucket (kernel-level rate limiting)

The token bucket parameters are set **dynamically per IP** from the matched rule:

| Parameter | Value |
|-----------|-------|
| Refill rate | `rule.Threshold` tokens / second (the matched rule's threshold) |
| Max capacity (burst) | `rule.Threshold × 2` tokens |

Packets are silently dropped when the token quota is exhausted. Block entries store an expiration timestamp in kernel nanoseconds (`bpf_ktime_get_ns`) and are enforced atomically on every packet without any user-space involvement.

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

Rules can be scoped to a specific environment via the `tag` field. Agents filter rules based on the `env` setting in `server.conf`:

- **Global rule** (empty `tag`): applied by all agents regardless of environment.
- **Tagged rule** (e.g. `tag: "production"`): applied only by agents where `env = "production"`.

Set the environment in `server.conf`:

```toml
# Production agent — receives global rules + "production" rules
env = "production"

# Staging agent — receives global rules + "staging" rules
env = "staging"

# Empty (default) — receives ALL rules
env = ""
```

---

## Requirements

| Dependency | Version |
|------------|---------|
| Ubuntu / Debian Linux | Kernel ≥ 5.9 |
| Go | **1.25+** |
| clang / llvm | Latest stable |
| libbpf-dev | Via apt |
| Linux headers | Matching active kernel |
| Docker + Docker Compose | For infrastructure (NATS + TimescaleDB + Grafana) |

---

## Installation

Run these steps once on a fresh Ubuntu/Debian machine before starting the system.

### 1. System packages

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev \
    linux-headers-$(uname -r) make git gcc curl wget
```

> **Note — missing `asm/types.h`:** On some Ubuntu/Debian systems the architecture-specific headers are not symlinked to `/usr/include/asm`, which causes clang and bpf2go to fail with `fatal error: 'asm/types.h' file not found`. Fix it with:
> ```bash
> sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
> ```

### 2. Go 1.25+

```bash
wget https://go.dev/dl/go1.25.9.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.9.linux-amd64.tar.gz
rm go1.25.9.linux-amd64.tar.gz
```

Add Go to your `PATH` (run once, then re-open your shell or `source ~/.bashrc`):

```bash
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

go version
```

### 3. Docker + Docker Compose

Required to run the infrastructure (TimescaleDB, NATS, Grafana):

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
sudo apt install -y docker-compose-plugin

docker --version
docker compose version
```

> Re-login (or run `newgrp docker`) so the group change takes effect before using `docker` without `sudo`.

### 4. Clone the repository

```bash
git clone https://github.com/ahmadsaflo1/ebpf-policy.git
cd ebpf-policy
```

### 5. Install Go build tool (bpf2go)

`bpf2go` genererar Go-bindningar från den kompilerade eBPF-koden. Installera det med:

```bash
go get -tool github.com/cilium/ebpf/cmd/bpf2go
```

> **Build dependencies — summary:** The following are required to compile the agent and eBPF program:
>
> | Dependency | How to install |
> |------------|----------------|
> | `clang` | `sudo apt install clang` |
> | `llvm` | `sudo apt install llvm` |
> | `libbpf-dev` | `sudo apt install libbpf-dev` |
> | `bpf2go` | `go get -tool github.com/cilium/ebpf/cmd/bpf2go` |

### 6. Find your network interface name

The agent monitors a specific network interface. Run this command to see the available interfaces:

```bash
ip link show
```

Common names: `eth0`, `ens3`, `ens5`, `enp0s5`. Note the name — you will need it in `server.conf`.

---

## Configuration

The webserver and agent are configured through a single TOML file (`server.conf` by default).

```toml
# Environment tag for this agent — filters which rules are applied.
# Leave empty to receive ALL rules (global + all tagged).
env = "production"

[server]
port    = 4040          # Web UI port
web_dir = "web/public"  # Static files directory

[nats]
url = "nats://localhost:4222"   # NATS broker address

[agent]
interface  = "enp0s5"                  # Network interface for eBPF (see: ip link show)
agent_id   = "agent-001"               # Unique name for this agent
server_url = "http://localhost:8080"   # Policy server REST API URL
```

> If `agent.interface` is left empty, the webserver starts without the eBPF agent — useful for development or when running without root access.

---

## Quick Start (using Make)

The Makefile wraps all steps. Infrastructure (TimescaleDB, NATS, Grafana) runs in Docker.

```bash
# 1. Start infrastructure (TimescaleDB, NATS, Grafana)
make start-infra

# 2. Build all binaries (compiles eBPF C code + Go binaries)
make build

# 3. In one terminal — start the policy server
make run-server

# 4. In a second terminal — start the webserver + agent
#    Edit server.conf first to set the correct interface (ip link show)
make run-webserver
```

Use a custom config file:

```bash
make run-webserver CONFIG=prod.conf
```

### Verify it is working

```bash
# Check that all containers are running
make status

# Web UI
http://<webserver-ip>:4040

# Policy REST API
http://<server-ip>:8080

# Grafana (login: admin / admin)
http://<server-ip>:3000
```

### Make targets

```bash
make build           # Build policy-server and webserver (includes eBPF)
make build-server    # Build policy server only
make build-webserver # Build webserver + agent (includes eBPF compilation)
make run-server      # Run the policy server
make run-webserver   # Run webserver + agent (requires sudo for eBPF)
make start-infra     # Start TimescaleDB, NATS, and Grafana containers
make stop-infra      # Stop infrastructure containers
make stop            # Stop all processes and containers
make status          # Show running infrastructure containers
make logs-db         # Stream TimescaleDB logs
make logs-nats       # Stream NATS logs
make logs-grafana    # Stream Grafana logs
make db-flush        # Remove TimescaleDB volume (wipes all data)
make clean           # Remove build artifacts
make help            # List all targets with descriptions
```

---

## Manual Build

Use this if you want to build without the Makefile shortcuts.

### 1. Start infrastructure

```bash
docker compose up -d
```

### 2. Build policy server

```bash
go build -o policy-server ./cmd/server/
```

### 3. Build webserver + agent (compiles eBPF + generates Go bindings + builds binary)

```bash
# Compile the eBPF C program to bytecode
cd ebpf && make && cd ..

# Generate Go bindings from the compiled bytecode
go generate ./internal/agent/ebpf

# Build the webserver binary (includes the agent)
go build -o webserver ./cmd/webserver/
```

| Generated file | Description |
|----------------|-------------|
| `internal/agent/ebpf/policy_bpfel.go` | Go bindings for little-endian (x86-64) |
| `internal/agent/ebpf/policy_bpfeb.go` | Go bindings for big-endian |
| `internal/agent/ebpf/policy_bpfel.o` | Compiled eBPF bytecode for little-endian |
| `internal/agent/ebpf/policy_bpfeb.o` | Compiled eBPF bytecode for big-endian |

---

## Running the System

### Policy Server

```bash
./policy-server
```

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `PORT` | `8080` | HTTP port the server listens on |
| `NATS_URL` | `nats://<server-ip>:4222` | NATS broker address |
| `USE_TIMESCALE` | *(unset = SQLite)* | Set to `true` to use TimescaleDB |
| `POSTGRES_HOST` | `<server-ip>` | TimescaleDB host |
| `POSTGRES_PORT` | `5432` | TimescaleDB port |
| `POSTGRES_USER` | `ebpf_user` | Database user |
| `POSTGRES_PASSWORD` | `ebpf_secret_password` | Database password |
| `POSTGRES_DB` | `policy_metrics` | Database name |

### Webserver + Agent

Requires root privileges to attach the XDP program to the network interface.

```bash
sudo ./webserver -c server.conf
```

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | *(none)* | Path to TOML config file |
| `-l` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `-f` | `text` | Log format: `text` or `json` |

All settings are in `server.conf` — see [Configuration](#configuration).

---

## Web UI

The webserver serves a built-in web interface at `http://<webserver>:4040/`.

### Tabs

| Tab | Description |
|-----|-------------|
| **Rules** | Create, view, edit, and delete policy rules with live validation |
| **Traffic** | Top clients by req/s / blocks / rate-limits; per-IP search; aggregated stats over a time range |
| **System** | Recent and aggregated system metrics (CPU, memory, disk, network I/O) per agent |

A live health indicator in the header reflects the policy server's `/health` endpoint status in real time.

---

## REST API

Base URL: `http://<server>:8080`

### Policy Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web UI (browser dashboard) |
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

Grafana is included in the Docker Compose stack and is automatically provisioned with a pre-built dashboard.

### Open the dashboard

After `make start-infra`, Grafana is available at:

```
http://<server-ip>:3000
```

Log in with username `admin` and password `admin`, then navigate to **Dashboards → Browse** and select **eBPF Policy Overview**.

> Replace `<server-ip>` with the IP address of the machine running the server. 

The dashboard is loaded automatically via provisioning from `grafana/dashboards/ebpf-policy-overview.json`. No manual steps are required.

### Troubleshooting

If the dashboard does not appear:

```bash
# Check that the containers are running
docker compose ps

# View logs
docker compose logs grafana

# Restart Grafana
docker compose restart grafana
```

If the containers fail to start:

```bash
docker compose down -v
docker compose up -d
```

---

## Database Schema

The database is created automatically on server startup. TimescaleDB uses hypertables with 1-day chunk intervals and automatic retention policies (30 days for traffic metrics, 7 days for system metrics).

**`policy_rules`**

```sql
id          SERIAL PRIMARY KEY
name        TEXT        NOT NULL
threshold   INTEGER     NOT NULL
action      TEXT        NOT NULL    -- "block" or "ratelimit"
duration    INTEGER     NOT NULL    -- seconds
tag         TEXT        NOT NULL DEFAULT ''   -- empty = global rule
created_at  TIMESTAMPTZ DEFAULT NOW()
```

**`client_stats`** — per-IP traffic metrics from agents (hypertable)

```sql
time           TIMESTAMPTZ NOT NULL
agent_id       TEXT        NOT NULL
ip             INET        NOT NULL
req_per_sec    INTEGER     NOT NULL
blocked        INTEGER     NOT NULL    -- 1 = currently blocked
rate_limited   INTEGER     NOT NULL    -- 1 = rate-limited
passed         INTEGER     NOT NULL
avg_latency_us BIGINT      DEFAULT 0   -- microseconds
min_latency_us BIGINT      DEFAULT 0
max_latency_us BIGINT      DEFAULT 0
```

**`system_metrics`** — agent system performance (hypertable)

```sql
time             TIMESTAMPTZ NOT NULL
agent_id         TEXT        NOT NULL
cpu_percent      INTEGER     NOT NULL    -- millipercent (×1000, e.g. 72500 = 72.5%)
memory_percent   INTEGER     NOT NULL    -- millipercent (×1000)
memory_used_mb   INTEGER     NOT NULL
memory_total_mb  INTEGER     NOT NULL
disk_used_gb     INTEGER     NOT NULL
disk_total_gb    INTEGER     NOT NULL
disk_percent     INTEGER     NOT NULL    -- millipercent (×1000)
net_bytes_sent   BIGINT      NOT NULL
net_bytes_recv   BIGINT      NOT NULL
```

---

## Technologies

| Technology | Usage |
|------------|-------|
| [cilium/ebpf](https://github.com/cilium/ebpf) | Loads and manages eBPF programs from Go |
| [NATS](https://nats.io) | Distributed pub/sub messaging |
| [BurntSushi/toml](https://github.com/BurntSushi/toml) | TOML configuration file parsing |
| Go stdlib `net/http` | HTTP server and REST API routing |
| [TimescaleDB](https://www.timescale.com) | Time-series PostgreSQL for metrics |
| `/proc` + `syscall.Statfs` | Linux-native system metrics (CPU, memory, disk, network I/O) |
| [Alpine.js](https://alpinejs.dev) + [Tailwind CSS](https://tailwindcss.com) | Reactive web UI (dark theme) |
| eBPF/XDP | Kernel-level packet filtering with minimal overhead |
