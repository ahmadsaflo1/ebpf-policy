package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// InitTimescale initializes connection to TimescaleDB and creates schema.
func InitTimescale(cfg Config) {
	var err error

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName)

	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Could not connect to TimescaleDB:", err)
	}

	// Test connection
	err = DB.Ping()
	if err != nil {
		log.Fatal("Could not ping TimescaleDB:", err)
	}

	err = createTimescaleTables()
	if err != nil {
		log.Fatal("Could not create TimescaleDB tables:", err)
	}

	log.Println("TimescaleDB connected!")
}

// createTimescaleTables creates all required tables and hypertables
func createTimescaleTables() error {
	// Enable TimescaleDB extension
	_, err := DB.Exec(`CREATE EXTENSION IF NOT EXISTS timescaledb;`)
	if err != nil {
		return fmt.Errorf("failed to create timescaledb extension: %w", err)
	}

	// Create policy_rules table (normal table, not time-series)
	_, err = DB.Exec(`
	CREATE TABLE IF NOT EXISTS policy_rules (
		id         SERIAL PRIMARY KEY,
		name       TEXT    NOT NULL,
		threshold  INTEGER NOT NULL,
		action     TEXT    NOT NULL,
		duration   INTEGER NOT NULL,
		tag        TEXT    NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	if err != nil {
		return fmt.Errorf("failed to create policy_rules: %w", err)
	}

	// Create client_stats table (time-series data)
	_, err = DB.Exec(`
	CREATE TABLE IF NOT EXISTS client_stats (
		time           TIMESTAMPTZ NOT NULL,
		agent_id       TEXT    NOT NULL,
		ip             INET    NOT NULL,
		req_per_sec    INTEGER NOT NULL,
		blocked        INTEGER NOT NULL,
		rate_limited   INTEGER NOT NULL DEFAULT 0,
		passed         INTEGER NOT NULL,
		avg_latency_us BIGINT  DEFAULT 0,
		min_latency_us BIGINT  DEFAULT 0,
		max_latency_us BIGINT  DEFAULT 0
	)`)
	if err != nil {
		return fmt.Errorf("failed to create client_stats: %w", err)
	}

	// Migrate existing databases that pre-date this column.
	DB.Exec(`ALTER TABLE client_stats ADD COLUMN IF NOT EXISTS rate_limited INTEGER NOT NULL DEFAULT 0`)

	// Convert to hypertable (TimescaleDB magic!)
	_, err = DB.Exec(`
	SELECT create_hypertable('client_stats', 'time',
		if_not_exists => TRUE,
		chunk_time_interval => INTERVAL '1 day'
	)`)
	if err != nil {
		return fmt.Errorf("failed to create hypertable: %w", err)
	}

	// Create index for faster queries
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_client_stats_ip ON client_stats (ip, time DESC)`)
	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_client_stats_agent ON client_stats (agent_id, time DESC)`)

	// Create system_metrics table (time-series data)
	_, err = DB.Exec(`
	CREATE TABLE IF NOT EXISTS system_metrics (
		time             TIMESTAMPTZ NOT NULL,
		agent_id         TEXT    NOT NULL,
		cpu_percent      INTEGER NOT NULL,
		memory_percent   INTEGER NOT NULL,
		memory_used_mb   INTEGER NOT NULL,
		memory_total_mb  INTEGER NOT NULL,
		disk_used_gb     INTEGER NOT NULL,
		disk_total_gb    INTEGER NOT NULL,
		disk_percent     INTEGER NOT NULL,
		net_bytes_sent   BIGINT  NOT NULL,
		net_bytes_recv   BIGINT  NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create system_metrics: %w", err)
	}

	// Convert to hypertable
	_, err = DB.Exec(`
	SELECT create_hypertable('system_metrics', 'time',
		if_not_exists => TRUE,
		chunk_time_interval => INTERVAL '1 day'
	)`)
	if err != nil {
		return fmt.Errorf("failed to create system_metrics hypertable: %w", err)
	}

	DB.Exec(`CREATE INDEX IF NOT EXISTS idx_system_metrics_agent ON system_metrics (agent_id, time DESC)`)

	// Add retention policies (auto-delete old data)
	// Keep client_stats for 30 days
	_, err = DB.Exec(`
	SELECT add_retention_policy('client_stats', INTERVAL '30 days', if_not_exists => TRUE)`)
	if err != nil {
		log.Printf("Warning: Could not add retention policy for client_stats: %v", err)
	}

	// Keep system_metrics for 7 days (less important, more volume)
	_, err = DB.Exec(`
	SELECT add_retention_policy('system_metrics', INTERVAL '7 days', if_not_exists => TRUE)`)
	if err != nil {
		log.Printf("Warning: Could not add retention policy for system_metrics: %v", err)
	}

	log.Println("✅ TimescaleDB tables and hypertables created")
	log.Println("✅ Retention policies: client_stats=30d, system_metrics=7d")

	return nil
}

