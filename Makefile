.PHONY: help build-server build-agent start-infra stop-infra run-server run-agent

# Default values (can be overridden)
INTERFACE ?= eth0
AGENT_ID ?= unknown
ENV ?=
SERVER_URL ?= http://localhost:8080
NATS_URL ?= nats://localhost:4222

help:
	@echo 'Usage: make [target] [VARIABLE=value]'
	@echo ''
	@echo 'Targets:'
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
	go build -o server ./cmd/server/

build-agent:
	@echo "Building eBPF program..."
	cd ebpf && make && cd ..
	@echo "Generating Go bindings..."
	cd internal/agent/ebpf && bpf2go -go-package ebpf Policy ../../../ebpf/policy.c && cd ../../..
	@echo "Building agent..."
	go build -o agent ./cmd/agent/

start-infra:
	@echo "Starting infrastructure (TimescaleDB + NATS + Grafana)..."
	docker-compose up -d
	@echo ""
	@echo "✅ Infrastructure started!"
	@echo "   TimescaleDB: localhost:5432"
	@echo "   NATS: localhost:4222"
	@echo "   NATS Monitoring: http://localhost:8222"
	@echo "   Grafana: http://localhost:3000 (username: admin, password: admin)"

stop-infra:
	@echo "Stopping infrastructure..."
	docker-compose down

run-server:
	@echo "Starting policy server with TimescaleDB..."
	@echo "API: http://localhost:8080"
	USE_TIMESCALE=true ./server

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
	     ./agent

status:
	@echo "Infrastructure Status:"
	@docker ps --filter "name=timescaledb" --filter "name=nats" --filter "name=grafana" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
logs-db:
	docker logs -f timescaledb

logs-nats:
	docker logs -f nats

logs-grafana:
	docker logs -f grafana

clean:
	@echo "Cleaning build artifacts..."
	rm -f server agent
	cd ebpf && make clean
	rm -f internal/agent/ebpf/policy_bpf*.go
	rm -f internal/agent/ebpf/policy_bpf*.o