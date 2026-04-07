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
        log.Fatal("Kunde inte öppna databasen:", err)
    }

    err = createTables()
    if err != nil {
        log.Fatal("Kunde inte skapa tabeller:", err)
    }

    log.Println("Databas ansluten!")
}

func createTables() error {
    query := `
    CREATE TABLE IF NOT EXISTS policy_rules (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT    NOT NULL,
        threshold  INTEGER NOT NULL,
        action     TEXT    NOT NULL,
        duration   INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`

    _, err := DB.Exec(query)
    return err
}