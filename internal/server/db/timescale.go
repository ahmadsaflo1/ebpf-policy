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
		topic      TEXT    NOT NULL DEFAULT '',
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

	// Migrate existing databases that pre-date these columns.
	DB.Exec(`ALTER TABLE client_stats ADD COLUMN IF NOT EXISTS rate_limited INTEGER NOT NULL DEFAULT 0`)
	DB.Exec(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='policy_rules' AND column_name='tag') THEN ALTER TABLE policy_rules RENAME COLUMN tag TO topic; END IF; END $$`)

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

	// Continuous aggregates — pre-computed rollups so historical queries are instant
	_, err = DB.Exec(`
	CREATE MATERIALIZED VIEW IF NOT EXISTS system_metrics_1m
	WITH (timescaledb.continuous) AS
	SELECT
		time_bucket('1 minute', time) AS bucket,
		agent_id,
		AVG(cpu_percent)         AS avg_cpu,
		AVG(memory_percent)      AS avg_memory,
		AVG(disk_percent)        AS avg_disk,
		AVG(net_bytes_sent)      AS avg_net_sent,
		AVG(net_bytes_recv)      AS avg_net_recv
	FROM system_metrics
	GROUP BY bucket, agent_id
	WITH NO DATA`)
	if err != nil {
		log.Printf("Warning: Could not create system_metrics_1m aggregate: %v", err)
	}

	_, err = DB.Exec(`
	CREATE MATERIALIZED VIEW IF NOT EXISTS client_stats_1m
	WITH (timescaledb.continuous) AS
	SELECT
		time_bucket('1 minute', time) AS bucket,
		agent_id,
		ip,
		AVG(req_per_sec)       AS avg_req_per_sec,
		SUM(blocked)           AS sum_blocked,
		SUM(rate_limited)      AS sum_rate_limited,
		SUM(passed)            AS sum_passed,
		AVG(avg_latency_us)    AS avg_latency_us,
		MIN(min_latency_us)    AS min_latency_us,
		MAX(max_latency_us)    AS max_latency_us
	FROM client_stats
	GROUP BY bucket, agent_id, ip
	WITH NO DATA`)
	if err != nil {
		log.Printf("Warning: Could not create client_stats_1m aggregate: %v", err)
	}

	// Refresh policies — keep aggregates up to date automatically
	DB.Exec(`
	SELECT add_continuous_aggregate_policy('system_metrics_1m',
		start_offset => INTERVAL '1 hour',
		end_offset   => INTERVAL '10 seconds',
		schedule_interval => INTERVAL '30 seconds',
		if_not_exists => TRUE)`)

	DB.Exec(`
	SELECT add_continuous_aggregate_policy('client_stats_1m',
		start_offset => INTERVAL '1 hour',
		end_offset   => INTERVAL '10 seconds',
		schedule_interval => INTERVAL '30 seconds',
		if_not_exists => TRUE)`)

	log.Println("✅ Continuous aggregates created: system_metrics_1m, client_stats_1m")

	// Add retention policies (auto-delete old data)
	// Keep client_stats for 7 days
	_, err = DB.Exec(`
	SELECT add_retention_policy('client_stats', INTERVAL '7 days', if_not_exists => TRUE)`)
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
	log.Println("✅ Retention policies: client_stats=7d, system_metrics=7d")

	return nil
}

