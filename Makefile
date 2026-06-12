# ─────────────────────────────────────────────
#  eBPF Policy — Makefile
# ─────────────────────────────────────────────

POLICYSERVER_CONFIG ?= policyserver.conf
WEBSERVER_CONFIG    ?= webserver.conf

# ─── Phony targets ────────────────────────────
.PHONY: \
  build build-policyserver build-webserver \
  start stop clean \
  start-infra stop-infra \
  run-policyserver run-webserver \
  install-service uninstall-service service-status \
  status db-flush \
  logs-db logs-nats logs-grafana logs-webserver logs-policyserver \
  help

# ─── Default ──────────────────────────────────
all: help

# ─────────────────────────────────────────────
#  Build
# ─────────────────────────────────────────────

build: build-policyserver build-webserver
	@echo ""
	@echo "  Build complete: policy-server and webserver ready."

build-policyserver:
	@echo "Building policy server..."
	go build -o policy-server ./cmd/policyserver/
	@echo "  policy-server ready"

build-webserver:
	@echo "Building eBPF program..."
	cd ebpf && make && cd ..
	@echo "Generating Go bindings..."
	go generate ./internal/agent/ebpf
	@echo "Building webserver..."
	go build -o webserver ./cmd/webserver/
	@echo "Setting eBPF capabilities..."
	sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./webserver
	@echo "  webserver ready"

clean:
	@echo "Cleaning build artifacts..."
	rm -f policy-server webserver
	cd ebpf && make clean
	rm -f internal/agent/ebpf/policy_bpf*.go
	rm -f internal/agent/ebpf/policy_bpf*.o
	@echo "  Clean done."

# ─────────────────────────────────────────────
#  Infrastructure (Docker Compose)
# ─────────────────────────────────────────────

start: start-infra

stop: stop-infra
	@echo "Stopping local processes..."
	- pkill -f ./webserver
	@echo "Done."

start-infra:
	@echo "Starting infrastructure (TimescaleDB + NATS + Grafana + policy-server)..."
	docker compose up -d --build
	@echo "Waiting for TimescaleDB to be ready..."
	@until docker exec timescaledb pg_isready -q; do sleep 1; done
	@echo ""
	@echo "  Infrastructure started!"
	@echo "  API:     http://localhost:8080"
	@echo "  Grafana: http://localhost:3000  (admin / admin)"

stop-infra:
	@echo "Stopping infrastructure..."
	docker compose down
	@echo "Infrastructure stopped."

status:
	@echo "Infrastructure Status:"
	@docker ps \
	  --filter "name=timescaledb" \
	  --filter "name=nats" \
	  --filter "name=grafana" \
	  --filter "name=policy-server" \
	  --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

db-flush:
	@echo "WARNING: This will destroy all database data!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	docker stop timescaledb && docker rm timescaledb
	docker volume rm ebpf-policy_timescaledb-data
	@echo "Database volume removed. Run 'make start' to start fresh."

# ─────────────────────────────────────────────
#  Run locally (without Docker)
# ─────────────────────────────────────────────

run-policyserver:
	@echo "Starting policy server (config: $(POLICYSERVER_CONFIG))..."
	./policy-server -c $(POLICYSERVER_CONFIG)

run-webserver:
	@echo "Starting webserver + agent (config: $(WEBSERVER_CONFIG))..."
	./webserver -c $(WEBSERVER_CONFIG) -f json

# ─────────────────────────────────────────────
#  Systemd Service
# ─────────────────────────────────────────────

install-service: build-webserver
	@echo "Installing ebpf-webserver systemd service..."
	sudo cp ebpf-webserver.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable ebpf-webserver
	sudo systemctl start ebpf-webserver
	@echo "  Service installed and started."
	@echo "  Logs: make logs-webserver"

uninstall-service: clean
	@echo "Removing ebpf-webserver systemd service..."
	sudo systemctl stop ebpf-webserver || true
	sudo systemctl disable ebpf-webserver || true
	sudo rm -f /etc/systemd/system/ebpf-webserver.service
	sudo systemctl daemon-reload
	@echo "  Service removed."

service-status:
	systemctl status ebpf-webserver --no-pager

# ─────────────────────────────────────────────
#  Logs
# ─────────────────────────────────────────────

logs-webserver:
	journalctl -u ebpf-webserver.service -f

logs-policyserver:
	docker logs -f policy-server

logs-db:
	docker logs -f timescaledb

logs-nats:
	docker logs -f nats

logs-grafana:
	docker logs -f grafana

# ─────────────────────────────────────────────
#  Help
# ─────────────────────────────────────────────

help:
	@echo ""
	@echo "Usage: make <target> [WEBSERVER_CONFIG=path] [POLICYSERVER_CONFIG=path]"
	@echo ""
	@echo "Build"
	@echo "  build                Build policy-server and webserver"
	@echo "  build-policyserver   Build only the policy server binary"
	@echo "  build-webserver      Build only the webserver + eBPF binary"
	@echo "  clean                Remove all build artifacts"
	@echo ""
	@echo "Infrastructure"
	@echo "  start                Start all Docker infrastructure"
	@echo "  stop                 Stop all Docker infrastructure"
	@echo "  status               Show container status"
	@echo "  db-flush             Destroy and recreate the database volume"
	@echo ""
	@echo "Run locally"
	@echo "  run-policyserver     Run policy server (no Docker)"
	@echo "  run-webserver        Run webserver + agent (requires eBPF caps)"
	@echo ""
	@echo "Systemd service"
	@echo "  install-service      Build and install as systemd service"
	@echo "  uninstall-service    Stop, disable and clean service"
	@echo "  service-status       Show service status"
	@echo ""
	@echo "Logs"
	@echo "  logs-webserver       Stream webserver journal logs"
	@echo "  logs-policyserver    Stream policy-server container logs"
	@echo "  logs-db              Stream TimescaleDB logs"
	@echo "  logs-nats            Stream NATS logs"
	@echo "  logs-grafana         Stream Grafana logs"
	@echo ""
