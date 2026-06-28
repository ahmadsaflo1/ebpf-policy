# eBPF Policy — Makefile

POLICYSERVER_CONFIG ?= policyserver.conf
WEBSERVER_CONFIG    ?= webserver.conf

# Phony targets
.PHONY: \
  build build-policyserver build-webserver \
  start stop clean \
  start-infra stop-infra \
  run-policyserver run-webserver \
  install-service uninstall-service service-status \
  status db-flush \
  logs-db logs-nats logs-grafana logs-webserver logs-policyserver \
  help

# Default
all: help

# Build

build: build-policyserver build-webserver ## Build policy-server and webserver
build-policyserver: ## Build only the policy server binary
	@echo "==> Building policy-server..."
	go build -o policy-server ./cmd/policyserver/
	@echo "==> policy-server ready"

build-webserver: ## Build only the webserver + eBPF binary
	@echo "==> Building eBPF program..."
	cd ebpf && make && cd ..
	@echo "==> Generating Go bindings..."
	go generate ./internal/agent/ebpf
	@echo "==> Building webserver..."
	go build -o webserver ./cmd/webserver/
	@echo "==> Setting eBPF capabilities..."
	sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./webserver
	@echo "==> webserver ready"

clean: ## Remove all build artifacts
	@echo "==> Removing build artifacts..."
	rm -f policy-server webserver
	cd ebpf && make clean
	rm -f internal/agent/ebpf/policy_bpf*.go
	rm -f internal/agent/ebpf/policy_bpf*.o
	@echo "==> Clean done."

# Infrastructure (Docker Compose)

start: start-infra ## Start all Docker infrastructure

stop: stop-infra ## Stop all Docker infrastructure and local processes
	@echo "==> Stopping local processes..."
	- pkill -f ./webserver
	@echo "==> Done."

start-infra: ## Start Docker Compose services and wait for DB
	@echo "==> Starting infrastructure..."
	docker compose up -d --build
	@echo "==> Waiting for TimescaleDB to be ready..."
	@until docker exec timescaledb pg_isready -q; do sleep 1; done
	@echo ""
	@echo "==> Infrastructure started!"
	@echo "  API:     http://localhost:8080"
	@echo "  Grafana: http://localhost:3000  (admin / admin)"

stop-infra: ## Stop Docker Compose services
	@echo "==> Stopping infrastructure..."
	docker compose down
	@echo "==> Infrastructure stopped."

status: ## Show container status
	@docker ps \
	  --filter "name=timescaledb" \
	  --filter "name=nats" \
	  --filter "name=grafana" \
	  --filter "name=policy-server" \
	  --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

db-flush: ## Destroy and recreate the database volume
	@echo "==> WARNING: This will destroy all database data!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	docker stop timescaledb && docker rm timescaledb
	docker volume rm ebpf-policy_timescaledb-data
	@echo "Database volume removed. Run 'make start' to start fresh."

# Run locally (without Docker)

run-policyserver: ## Run policy server without Docker
	./policy-server -c $(POLICYSERVER_CONFIG)

run-webserver: ## Run webserver + agent (requires eBPF caps)
	./webserver -c $(WEBSERVER_CONFIG) -f json

# Systemd service

install-service: build-webserver ## Build and install as systemd service
	@echo "==> Installing ebpf-webserver systemd service..."
	sudo cp ebpf-webserver.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable ebpf-webserver
	sudo systemctl start ebpf-webserver
	@echo "==> Service started. Logs: make logs-webserver"

uninstall-service: clean ## Stop, disable and remove systemd service
	@echo "==> Removing ebpf-webserver systemd service..."
	sudo systemctl stop ebpf-webserver || true
	sudo systemctl disable ebpf-webserver || true
	sudo rm -f /etc/systemd/system/ebpf-webserver.service
	sudo systemctl daemon-reload

service-status: ## Show systemd service status
	systemctl status ebpf-webserver --no-pager

# Logs

logs-webserver: ## Stream webserver journal logs
	journalctl -u ebpf-webserver.service -f

logs-policyserver: ## Stream policy-server container logs
	docker logs -f policy-server

logs-db: ## Stream TimescaleDB logs
	docker logs -f timescaledb

logs-nats: ## Stream NATS logs
	docker logs -f nats

logs-grafana: ## Stream Grafana logs
	docker logs -f grafana

# Help

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-22s\033[0m %s\n", $$1, $$2}'
