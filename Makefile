.PHONY: build start stop help build-server build-webserver start-infra stop-infra run-server run-webserver db-flush clean status logs-db logs-nats logs-grafana

CONFIG ?= server.conf

build: build-server build-webserver
	@echo ""
	@echo " Build complete: policy-server and webserver ready."

start: start-infra run-server

stop: stop-infra
	@echo "Stopping processes..."
	- sudo pkill -f ./policy-server
	- sudo pkill -f ./webserver
	@echo "Done."

clean:
	@echo "Cleaning build artifacts..."
	rm -f policy-server webserver
	cd ebpf && make clean
	rm -f internal/agent/ebpf/policy_bpf*.go
	rm -f internal/agent/ebpf/policy_bpf*.o
	@echo "Clean done."

help:
	@echo 'Usage: make [target] [CONFIG=path/to/config.conf]'
	@echo ''
	@echo 'Targets:'
	@echo '  build           - Build policy-server and webserver (includes eBPF)'
	@echo '  start           - Start infra and policy server'
	@echo '  stop            - Stop all processes and infrastructure'
	@echo '  clean           - Remove binaries and eBPF build artifacts'
	@echo '  build-server    - Build policy server'
	@echo '  build-webserver - Build webserver + agent (includes eBPF compilation)'
	@echo '  start-infra     - Start TimescaleDB, NATS, and Grafana containers'
	@echo '  stop-infra      - Stop infrastructure containers'
	@echo '  run-server      - Run policy server'
	@echo '  run-webserver   - Run webserver + agent (requires sudo for eBPF)'
	@echo '  status          - Show infrastructure container status'
	@echo '  db-flush        - Remove database volume (destructive)'
	@echo ''
	@echo 'Config variable:'
	@echo '  CONFIG          - Path to config file (default: server.conf)'
	@echo ''
	@echo 'Examples:'
	@echo '  make build'
	@echo '  make run-webserver'
	@echo '  make run-webserver CONFIG=sever.conf'

build-server:
	@echo "Building policy server..."
	go build -o policy-server ./cmd/policyserver/
	@echo "Server binary ready: ./policy-server"

build-webserver:
	@echo "Building eBPF program..."
	cd ebpf && make && cd ..
	@echo "Generating Go bindings..."
	go generate ./internal/agent/ebpf
	@echo "Building webserver..."
	go build -o webserver ./cmd/webserver/
	@echo "Webserver binary ready: ./webserver"

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
	@echo "Starting policy server (config: $(CONFIG))..."
	@echo "API:     http://localhost:8080"
	@echo "Grafana: http://localhost:3000 (admin / admin)"
	@echo ""
	@echo "Start the agent separately with 'make run-agent' to connect to this server."
	@echo ""
	./policy-server -c $(CONFIG)

run-webserver:
	@echo "Starting webserver + agent (config: $(CONFIG))..."
	@echo "Webserver: http://localhost:4040"
	sudo ./webserver -c $(CONFIG)

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
