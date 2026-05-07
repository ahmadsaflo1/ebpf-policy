.PHONY: build start stop help build-server build-agent start-infra stop-infra run-server run-agent db-flush

# Default values (can be overridden)
INTERFACE ?= eth0
AGENT_ID ?= unknown
ENV ?=
SERVER_URL ?= http://localhost:8080
NATS_URL ?= nats://localhost:4222

build: build-server build-agent
	@echo ""
	@echo " Build complete: server and agent ready."

start: start-infra run-server

stop: stop-infra
	@echo "Stopping server and agent..."
	- sudo pkill -f ./policy-server
	- sudo pkill -f ./policy-agent
	@echo "Done."

clean:
	@echo "Cleaning build artifacts..."
	rm -f policy-server policy-agent
	cd ebpf && make clean
	rm -f internal/agent/ebpf/policy_bpf*.go
	rm -f internal/agent/ebpf/policy_bpf*.o
	@echo "Clean done."

help:
	@echo 'Usage: make [target] [VARIABLE=value]'
	@echo ''
	@echo 'Targets:'
	@echo '  build           - Build server and agent'
	@echo '  start           - Start infra, server and agent'
	@echo '  stop            - Stop infrastructure containers'
	@echo '  build-server    - Build policy server'
	@echo '  build-agent     - Build policy agent (includes eBPF compilation)'
	@echo '  start-infra     - Start TimescaleDB and NATS containers'
	@echo '  stop-infra      - Stop infrastructure containers'
	@echo '  run-server      - Run policy server with TimescaleDB'
	@echo '  run-agent       - Run policy agent (requires sudo)'
	@echo ''
	@echo 'Agent Variables (override with VARIABLE=value):'
	@echo '  INTERFACE       - Network interface (default: eth0)'
	@echo '  AGENT_ID        - Agent identifier (default: unknown)'
	@echo '  ENV             - Environment tag (default: "" - receives ALL rules)'
	@echo '  SERVER_URL      - Policy server URL (default: http://localhost:8080)'
	@echo '  NATS_URL        - NATS broker URL (default: nats://localhost:4222)'
	@echo ''
	@echo 'Environment Tag Examples:'
	@echo '  ENV=""            - Receives ALL rules (global + tagged)'
	@echo '  ENV=production    - Receives global + production rules only'
	@echo '  ENV=staging       - Receives global + staging rules only'
	@echo ''
	@echo 'Examples:'
	@echo '  make run-agent                                    # Default (all rules)'
	@echo '  make run-agent AGENT_ID=prod-agent-1 ENV=production'
	@echo '  make run-agent AGENT_ID=staging-agent ENV=staging'
	@echo '  make run-agent INTERFACE=ens5 AGENT_ID=test-1'

build-server:
	@echo "Building policy server..."
	go build -o policy-server ./cmd/server/
	@echo "Server binary ready: ./policy-server"

build-agent:
	@echo "Building eBPF program..."
	cd ebpf && make && cd ..
	@echo "Generating Go bindings..."
	go generate ./internal/agent/ebpf
	@echo "Building agent..."
	go build -o policy-agent ./cmd/agent/
	@echo "Agent binary ready: ./policy-agent"

start-infra:
	@echo "Starting infrastructure (TimescaleDB + NATS + Grafana)..."
	docker compose up -d
	@echo ""
	@echo "   Infrastructure started!"

stop-infra:
	@echo "Stopping infrastructure..."
	docker compose down
	@echo "Infrastructure stopped."

run-server:
	@echo "Starting policy server with TimescaleDB..."
	@echo "API: http://localhost:8080"
	@echo "Grafana: http://localhost:3000 (username: admin, password: admin)"
	@echo ""
	@echo "Start the agent separately with 'make run-agent' to connect to this server."
	@echo ""
	USE_TIMESCALE=true ./policy-server

run-agent:
	@echo "Starting agent with configuration:"
	@echo "  INTERFACE: $(INTERFACE)"
	@echo "  AGENT_ID: $(AGENT_ID)"
	@echo "  ENV: $(if $(ENV),$(ENV),<empty - receives ALL rules>)"
	@echo "  SERVER_URL: $(SERVER_URL)"
	@echo "  NATS_URL: $(NATS_URL)"
	@echo ""
	sudo INTERFACE=$(INTERFACE) \
	     AGENT_ID=$(AGENT_ID) \
	     ENV=$(ENV) \
	     SERVER_URL=$(SERVER_URL) \
	     NATS_URL=$(NATS_URL) \
	     ./policy-agent

db-flush:
	@echo "Removing database volume..."
	docker stop timescaledb && docker rm timescaledb
	docker volume rm ebpf-policy_timescaledb-data
	@echo "Database volume removed. Run 'make start' to start fresh."

status:
	@echo "Infrastructure Status:"
	@docker ps --filter "name=timescaledb" --filter "name=nats" --filter "name=grafana" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

logs-db:
	@echo "Streaming TimescaleDB logs (Ctrl+C to exit)..."
	docker logs -f timescaledb

logs-nats:
	@echo "Streaming NATS logs (Ctrl+C to exit)..."
	docker logs -f nats

logs-grafana:
	@echo "Streaming Grafana logs (Ctrl+C to exit)..."
	docker logs -f grafana
