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
- [Running the System](#running-the-system)
- [Running the agent on an additional machine](#running-the-agent-on-an-additional-machine)
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
│   Metrics + log collection   │
└──────────────┬───────────────┘
               │
           NATS pub/sub + JetStream
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

| Binary | Config file | Description |
|--------|-------------|-------------|
| **`policy-server`** | `policyserver.conf` | Central control plane — manages rules via REST API, persists data to TimescaleDB, distributes changes via NATS, collects metrics and logs |
| **`webserver`** | `webserver.conf` | Serves the web UI and runs the embedded eBPF/XDP agent |

### Components

| Component | Description |
|-----------|-------------|
| **Policy Server** | Stores rules, collects metrics and logs, pushes updates to agents via NATS |
| **Agent** | Embedded in the webserver binary — loads the eBPF program, enforces rules, reports metrics |
| **eBPF/XDP** | Kernel-space C program that filters packets at the network interface with microsecond latency |
| **NATS + JetStream** | Message broker for policy distribution, metrics aggregation, and guaranteed log delivery |

### NATS Topics

| Topic | Direction | Delivery | Purpose |
|-------|-----------|----------|---------|
| `policy.update` | Server → Agents | Core NATS | New or updated global rule |
| `policy.update.<tag>` | Server → Agents | Core NATS | New or updated rule for a specific environment |
| `policy.delete` | Server → Agents | Core NATS | Deleted global rule |
| `policy.delete.<tag>` | Server → Agents | Core NATS | Deleted rule for a specific environment |
| `policy.fetch` | Agents → Server | Core NATS (req/reply) | Agent requests full rule set on startup |
| `metrics.report` | Agents → Server | Core NATS | Per-IP traffic stats (every 10 s) |
| `system.metrics` | Agents → Server | Core NATS | System performance metrics (every 30 s) |
| `log.>` | Agents → Server | **JetStream** | Structured JSON log lines — guaranteed delivery |

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

**Log delivery (per agent, per log line):**

```
  → slog writes JSON log line
  → natsWriter publishes to JetStream "log.webserver"
  → Policy server receives via "log.>" subscription
  → json.Unmarshal into map[string]any
  → Logged and available for storage/forwarding
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

Every 10 seconds the agent reads the eBPF `request_count` map, computes `req/s = delta / 10` per IP, and finds the winning rule:

1. Collect all rules where `reqPerSec >= rule.Threshold`.
2. **`block` always takes priority over `rate_limit`.**
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

| Parameter | Value |
|-----------|-------|
| Refill rate | `rule.Threshold` tokens / second |
| Max capacity (burst) | `rule.Threshold × 2` tokens |

### Agent Resilience

| Situation | Behavior |
|-----------|----------|
| Server reachable at startup | Fetches rules via NATS `policy.fetch` (req/reply, 5 s timeout) |
| NATS fetch fails | Falls back to HTTP `/api/rules`, retries 4 times (5 s interval) |
| HTTP also unavailable | Falls back to disk cache (`/tmp/ebpf-policy-rules.json`) |
| No disk cache and server down | Starts without rules, keeps retrying |
| Server comes back online | Fetches fresh rules automatically (health check every 15 s) |
| NATS connection drops | Reconnects with 5 s interval |

Rule cache is saved to `/tmp/ebpf-policy-rules.json` and updated on every successful fetch.

---

## Environment Tags

Rules can be scoped to a specific environment via the `topic` field. Agents filter rules based on the `env` setting in `webserver.conf`:

- **Global rule** (empty `topic`): applied by all agents regardless of environment.
- **Tagged rule** (e.g. `topic: "production"`): applied only by agents where `agent.topic = "production"`.

Set the environment in `webserver.conf`:

```toml
# Production agent — receives global rules + "production" rules
[agent]
topic = "production"

# Staging agent — receives global rules + "staging" rules
[agent]
topic = "staging"

# Empty (default) — receives ALL rules
[agent]
topic = ""
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

Common names: `eth0`, `ens3`, `ens5`, `enp0s5`. Set this in `webserver.conf` under `agent.interface`.

---

## Configuration

The system uses two separate config files — one per binary.

### `policyserver.conf` — central policy server

```toml
env = "prod"

[server]
port = 8080   # REST API port

[nats]
url = "nats://localhost:4222"

[postgres]
host     = "localhost"
port     = 5432
user     = "ebpf_user"
password = "ebpf_secret_password"
db       = "policy_metrics"
```

### `webserver.conf` — webserver + agent on each edge machine

```toml
env = "prod"

[server]
port    = 4040          # web UI port
altport = 80            # HTTP port (only needed with Let's Encrypt)
webdir  = "web/public"

# HTTPS with Let's Encrypt (requires a domain name):
letsencrypt = false
contact     = ""        # email for Let's Encrypt notifications
domains     = ["yourdomain.com"]

[nats]
url = "nats://localhost:4222"   # replace localhost with server IP if on a different machine

[agent]
interface = "enp0s5"            # network interface for eBPF (ip link show)
agentid   = "agent-1"
serverurl = "http://localhost:8080"   # replace localhost with server IP if on a different machine
topic     = "production"        # leave empty for all topics
```

> If `agent.interface` is left empty, the webserver starts without the eBPF agent — useful for development or when running without root access.

> **Running the agent on a separate machine:** Only the `webserver` binary needs to run on each edge machine. Replace `localhost` in `nats.url` and `agent.serverurl` with the policy server's IP address. See [Running the agent on an additional machine](#running-the-agent-on-an-additional-machine).

---

## Quick Start (using Make)

The Makefile wraps all steps. The policy server and all infrastructure (TimescaleDB, NATS, Grafana) run in Docker with `restart: unless-stopped`, so they survive reboots and crashes automatically.

### Server machine

```bash
# 1. Build the webserver + eBPF agent (policy-server is built inside Docker)
make build-webserver

# 2. Start everything — builds the policy-server Docker image, then starts
#    TimescaleDB, NATS, Grafana, and policy-server. Waits until DB is ready.
make start
```

Policy server and infrastructure are now running persistently. To stop them:

```bash
make stop
```

### Edge machine (webserver + eBPF agent)

Edit `webserver.conf` first — set `agent.interface` (run `ip link show` to find the interface name) and update `nats.url` / `agent.serverurl` with the server's IP address.

**Development (foreground, logs to terminal):**

```bash
make run-webserver
```

**Production (persistent systemd service — survives reboots, restarts on failure):**

```bash
# Install and start the service (runs as the ubuntu user, not root)
make install-service

# View live logs
make logs-webserver

# Check status
make service-status

# Remove the service
make uninstall-service
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
make build                # Build policy-server and webserver (includes eBPF)
make build-policyserver   # Build policy server binary only
make build-webserver      # Build webserver + agent (includes eBPF compilation + setcap)
make start                # Start all infra + policy-server (docker compose)
make stop                 # Stop all infra and webserver
make start-infra          # Same as start
make stop-infra           # Stop infrastructure containers
make run-policyserver     # Run policy server locally without Docker
make run-webserver        # Run webserver + agent in foreground (JSON log mode)
make install-service      # Install webserver as a persistent systemd service
make uninstall-service    # Remove the systemd service
make service-status       # Show systemd service status
make status               # Show running infrastructure containers
make logs-webserver       # Stream webserver logs (systemd)
make logs-policyserver    # Stream policy-server logs (Docker)
make logs-db              # Stream TimescaleDB logs
make logs-nats            # Stream NATS logs
make logs-grafana         # Stream Grafana logs
make db-flush             # Remove TimescaleDB volume (wipes all data)
make clean                # Remove build artifacts
make help                 # List all targets
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
go build -o policy-server ./cmd/policyserver/
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

The policy server runs inside Docker as part of the `docker compose` stack. It starts automatically with `make start` and restarts on failure or machine reboot.

To run it locally outside Docker (e.g. for development):

```bash
./policy-server -c policyserver.conf
```

### Webserver + Agent

Grant capabilities once after each build (allows running without `sudo`):

```bash
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./webserver
```

```bash
./webserver -c webserver.conf -f json
```

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | *(none)* | Path to TOML config file |
| `-l` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `-f` | `text` | Log format: `text` or `json` (use `json` so policy server can parse logs) |
| `-q` | `false` | Quiet mode — disable stdout, send logs to NATS JetStream only |

> **Note:** Run the webserver with `-f json` so the policy server can unmarshal log lines received via NATS JetStream on `log.>`.

---

## Running the agent on an additional machine

Only the `webserver` binary and `webserver.conf` are needed on each edge machine. The policy server and infrastructure stay on the central server.

### 1. Install dependencies on the edge machine

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) make git gcc
```

Install Go and clone the repository (see [Installation](#installation)).

### 2. Build the webserver

```bash
make build-webserver
```

### 3. Configure

Edit `webserver.conf` — replace `localhost` with the policy server's IP address:

```toml
[nats]
url = "nats://<server-ip>:4222"

[agent]
interface = "eth0"           # run: ip link show
agentid   = "agent-2"        # unique per machine
serverurl = "http://<server-ip>:8080"
topic     = "production"
```

### 4. Run

**Foreground:**

```bash
make run-webserver
```

**Persistent service (survives reboots, runs as non-root):**

```bash
make install-service

# Logs
make logs-webserver
```

To update the binary on an edge machine after a code change:

```bash
make build-webserver
sudo systemctl restart ebpf-webserver
```

---

### HTTPS with Let's Encrypt

To serve the web UI over HTTPS, set in `webserver.conf`:

```toml
[server]
port        = 443
altport     = 80       # for ACME HTTP challenge and HTTP→HTTPS redirect
letsencrypt = true
contact     = "your@email.com"
domains     = ["yourdomain.com"]
```

Requires port 80 and 443 open in the firewall, and the domain must point to the machine's IP.

---

## Web UI

Available at `http://<webserver-ip>:4040/`

| Tab | Description |
|-----|-------------|
| **Rules** | Create, view, edit, and delete policy rules |
| **Traffic** | Top clients by req/s / blocks / rate-limits; per-IP search; aggregated stats |
| **System** | Recent and aggregated system metrics (CPU, memory, disk, network I/O) per agent |

---

## REST API

Base URL: `http://<server>:8080`

### Policy Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Server health check |
| `GET` | `/api/rules` | List all rules |
| `POST` | `/api/rules` | Create a new rule |
| `GET` | `/api/rules/{id}` | Get a specific rule |
| `PUT` | `/api/rules/{id}` | Update a rule |
| `DELETE` | `/api/rules/{id}` | Delete a rule |

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
    "action": "rate_limit",
    "duration": 30,
    "topic": "production"
  }'
```

### Rule schema

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Descriptive name |
| `threshold` | `int` | Requests per second trigger threshold |
| `action` | `string` | `"block"` or `"rate_limit"` |
| `duration` | `int` | Enforcement duration in seconds |
| `topic` | `string` | *(optional)* Environment tag — empty = global |

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

Created automatically on server startup. TimescaleDB hypertables use 1-day chunk intervals.

**`policy_rules`**

```sql
id          SERIAL PRIMARY KEY
name        TEXT        NOT NULL
threshold   INTEGER     NOT NULL
action      TEXT        NOT NULL    -- "block" or "rate_limit"
duration    INTEGER     NOT NULL    -- seconds
topic       TEXT        NOT NULL DEFAULT ''   -- empty = global rule
created_at  TIMESTAMPTZ DEFAULT NOW()
```

**`client_stats`** — per-IP traffic metrics (7-day retention)

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

**`system_metrics`** — agent system performance (7-day retention)

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
| [NATS + JetStream](https://nats.io) | Distributed pub/sub messaging with guaranteed log delivery |
| [BurntSushi/toml](https://github.com/BurntSushi/toml) | TOML configuration file parsing |
| Go stdlib `net/http` | HTTP server and REST API routing |
| [TimescaleDB](https://www.timescale.com) | Time-series PostgreSQL for metrics |
| `/proc` + `syscall.Statfs` | Linux-native system metrics (CPU, memory, disk, network I/O) |
| [Alpine.js](https://alpinejs.dev) + [Tailwind CSS](https://tailwindcss.com) | Reactive web UI |
| eBPF/XDP | Kernel-level packet filtering with minimal overhead |
| `golang.org/x/crypto/acme/autocert` | Automatic TLS certificates via Let's Encrypt |
