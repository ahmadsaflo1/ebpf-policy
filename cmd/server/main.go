// Command server starts the policy management HTTP server.
// It exposes a REST API for CRUD operations on policy rules, publishes rule
// changes to NATS so agents receive them in real time, and collects metrics
// reported by agents.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/api"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/metrics"
	"github.com/ahmadsaflo1/ebpf-policy/web"
)

type serverConfig struct {
	port       string
	natsURL    string
	pgHost     string
	pgPort     string
	pgUser     string
	pgPassword string
	pgDB       string
}

func loadConfig() serverConfig {
	var cfg serverConfig
	flag.StringVar(&cfg.port, "port", envOr("PORT", "8080"), "HTTP listen port")
	flag.StringVar(&cfg.natsURL, "nats-url", envOr("NATS_URL", "nats://localhost:4222"), "NATS server URL")
	flag.StringVar(&cfg.pgHost, "pg-host", envOr("POSTGRES_HOST", "localhost"), "PostgreSQL host")
	flag.StringVar(&cfg.pgPort, "pg-port", envOr("POSTGRES_PORT", "5432"), "PostgreSQL port")
	flag.StringVar(&cfg.pgUser, "pg-user", envOr("POSTGRES_USER", "ebpf_user"), "PostgreSQL user")
	flag.StringVar(&cfg.pgPassword, "pg-password", envOr("POSTGRES_PASSWORD", "ebpf_secret_password"), "PostgreSQL password")
	flag.StringVar(&cfg.pgDB, "pg-db", envOr("POSTGRES_DB", "policy_metrics"), "PostgreSQL database name")
	flag.Parse()
	return cfg
}

// envOr returns the environment variable value or def when unset.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := loadConfig()

	db.Init(db.Config{
		Host:     cfg.pgHost,
		Port:     cfg.pgPort,
		User:     cfg.pgUser,
		Password: cfg.pgPassword,
		DBName:   cfg.pgDB,
	})
	messaging.Init(cfg.natsURL)
	defer messaging.Close()

	metrics.StartCollector()
	metrics.StartSystemCollector()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web.Templates, "templates/index.html")
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /api/rules", api.GetRules)
	mux.HandleFunc("POST /api/rules", api.CreateRule)
	mux.HandleFunc("GET /api/rules/{id}", api.GetRule)
	mux.HandleFunc("PUT /api/rules/{id}", api.UpdateRule)
	mux.HandleFunc("DELETE /api/rules/{id}", api.DeleteRule)

	mux.HandleFunc("GET /api/metrics/search", api.SearchClients)
	mux.HandleFunc("GET /api/metrics/aggregated", api.GetAggregatedMetrics)
	mux.HandleFunc("GET /api/metrics/top", api.GetTopClients)

	mux.HandleFunc("GET /api/system/metrics/aggregated", api.GetSystemMetricsAggregated)
	mux.HandleFunc("GET /api/system/metrics", api.GetSystemMetrics)

	srv := &http.Server{
		Addr:    ":" + cfg.port,
		Handler: mux,
	}

	go func() {
		log.Printf("Starting server on %s ...", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server crashed: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("Server gracefully stopped")
}

