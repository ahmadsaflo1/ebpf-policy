.PHONY: build start stop help build-policyserver build-webserver start-infra stop-infra run-policyserver run-webserver db-flush clean status logs-db logs-nats logs-grafana set-caps

POLICYSERVER_CONFIG ?= policyserver.conf
WEBSERVER_CONFIG    ?= webserver.conf

build: build-policyserver build-webserver
	@echo ""
	@echo " Build complete: policy-server and webserver ready."

start: start-infra run-policyserver

stop: stop-infra
	@echo "Stopping processes..."
	- pkill -f ./policy-server
	- pkill -f ./webserver
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
	@echo '  build-policyserver - Build policy server'
	@echo '  build-webserver    - Build webserver + agent (includes eBPF compilation)'
	@echo '  start-infra        - Start TimescaleDB, NATS, and Grafana containers'
	@echo '  stop-infra         - Stop infrastructure containers'
	@echo '  run-policyserver   - Run policy server'
	@echo '  run-webserver   - Run webserver + agent (requires eBPF capabilities, run make set-caps first)'
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

build-policyserver:
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
	@echo "Setting eBPF capabilities on webserver binary..."
	sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./webserver
	@echo "Webserver binary ready: ./webserver"

start-infra:
	@echo "Starting infrastructure (TimescaleDB + NATS + Grafana)..."
	docker compose up -d
	@echo "Waiting for TimescaleDB to be ready..."
	@until docker exec timescaledb pg_isready -q; do sleep 1; done
	@echo ""
	@echo "   Infrastructure started!"

stop-infra:
	@echo "Stopping infrastructure..."
	docker compose down
	@echo "Infrastructure stopped."

run-policyserver:
	@echo "Starting policy server (config: $(POLICYSERVER_CONFIG))..."
	@echo "API:     http://localhost:8080"
	@echo "Grafana: http://localhost:3000 (admin / admin)"
	@echo ""
	./policy-server -c $(POLICYSERVER_CONFIG)

run-webserver:
	@echo "Starting webserver + agent (config: $(WEBSERVER_CONFIG))..."
	./webserver -c $(WEBSERVER_CONFIG) -f json

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
