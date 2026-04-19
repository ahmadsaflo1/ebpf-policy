// Package db manages the SQLite database connection and schema for the policy
// server.
package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// DB is the shared database connection used by HTTP handlers.
var DB *sql.DB

// Init opens (or creates) the SQLite database file and ensures the required
// tables exist. Calls log.Fatal on any error.
func Init() {
    var err error
    DB, err = sql.Open("sqlite3", "./policy.db")
    if err != nil {
        log.Fatal("could not open database:", err)
    }

    err = createTables()
    if err != nil {
        log.Fatal("could not create tables:", err)
    }

    log.Println("Database connected!")
}

// createTables creates the policy_rules and client_stats tables if they do
// not already exist.
func createTables() error {
    _, err := DB.Exec(`
    CREATE TABLE IF NOT EXISTS policy_rules (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT    NOT NULL,
        threshold  INTEGER NOT NULL,
        action     TEXT    NOT NULL,
        duration   INTEGER NOT NULL,
        tag        TEXT    NOT NULL DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
    if err != nil {
        return err
    }

    _, err = DB.Exec(`
    CREATE TABLE IF NOT EXISTS client_stats (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT    NOT NULL,
        ip          TEXT    NOT NULL,
        req_per_sec INTEGER NOT NULL,
        blocked     INTEGER NOT NULL,
        passed      INTEGER NOT NULL,
        recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)

    return err
}