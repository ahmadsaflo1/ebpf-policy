package db

import (
	"database/sql"
	"log"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

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

func createTables() error {
    _, err := DB.Exec(`
    CREATE TABLE IF NOT EXISTS policy_rules (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT    NOT NULL,
        threshold  INTEGER NOT NULL,
        action     TEXT    NOT NULL,
        duration   INTEGER NOT NULL,
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