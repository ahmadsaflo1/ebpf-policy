package db

import (
	"database/sql"
)

// Config holds the PostgreSQL connection parameters.
type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
}

// DB is the shared database connection used by HTTP handlers.
var DB *sql.DB

// Init initializes the TimescaleDB connection using the given config.
func Init(cfg Config) {
	InitTimescale(cfg)
}
