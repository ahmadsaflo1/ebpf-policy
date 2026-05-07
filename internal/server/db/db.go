package db

import (
	"database/sql"
)

// DB is the shared database connection used by HTTP handlers.
var DB *sql.DB

// Init initializes the TimescaleDB connection.
func Init() {
	InitTimescale()
}
