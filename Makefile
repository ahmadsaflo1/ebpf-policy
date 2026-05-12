.PHONY: build start stop help build-policyserver build-webserver start-infra stop-infra run-policyserver run-webserver db-flush clean status logs-db logs-nats logs-grafana logs-webserver logs-policyserver set-caps install-service uninstall-service service-status

POLICYSERVER_CONFIG ?= policyserver.conf
WEBSERVER_CONFIG    ?= webserver.conf

build: build-policyserver build-webserver
	@echo ""
	@echo " Build complete: policy-server and webserver ready."

start: start-infra

stop: stop-infra
	@echo "Stopping processes..."
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
	@echo '  build              - Build policy-server and webserver (includes eBPF)'
	@echo '  start              - Start all infra + policy-server (docker compose)'
	@echo '  stop               - Stop all infra and webserver'
	@echo '  clean              - Remove binaries and eBPF build artifacts'
	@echo '  build-policyserver - Build policy server binary'
	@echo '  build-webserver    - Build webserver + agent (includes eBPF compilation)'
	@echo '  start-infra        - Start TimescaleDB, NATS, Grafana, and policy-server'
	@echo '  stop-infra         - Stop infrastructure containers'
	@echo '  run-policyserver   - Run policy server locally (without Docker)'
	@echo '  run-webserver      - Run webserver + agent (requires eBPF capabilities)'
	@echo '  install-service    - Install ebpf-webserver as a systemd service'
	@echo '  uninstall-service  - Remove ebpf-webserver systemd service'
	@echo '  service-status     - Show ebpf-webserver service status'
	@echo '  status             - Show infrastructure container status'
	@echo '  db-flush           - Remove database volume (destructive)'
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
	@echo "Starting infrastructure (TimescaleDB + NATS + Grafana + policy-server)..."
	docker compose up -d --build
	@echo "Waiting for TimescaleDB to be ready..."
	@until docker exec timescaledb pg_isready -q; do sleep 1; done
	@echo ""
	@echo "   Infrastructure started!"
	@echo "   API:     http://localhost:8080"
	@echo "   Grafana: http://localhost:3000 (admin / admin)"

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

install-service:
	@echo "Installing ebpf-webserver systemd service..."
	sudo cp ebpf-webserver.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable ebpf-webserver
	sudo systemctl start ebpf-webserver
	@echo "Service installed and started. Logs: journalctl -u ebpf-webserver -f"

uninstall-service:
	@echo "Removing ebpf-webserver systemd service..."
	sudo systemctl stop ebpf-webserver || true
	sudo systemctl disable ebpf-webserver || true
	sudo rm -f /etc/systemd/system/ebpf-webserver.service
	sudo systemctl daemon-reload
	@echo "Service removed."

service-status:
	systemctl status ebpf-webserver --no-pager

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

logs-webserver:
	@echo "Streaming webserver logs (Ctrl+C to exit)..."
	journalctl -u ebpf-webserver.service -f

logs-policyserver:
	@echo "Streaming policy-server logs (Ctrl+C to exit)..."
	docker logs -f policy-server
