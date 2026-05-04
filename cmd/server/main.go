// Command server starts the policy management HTTP server.
// It exposes a REST API for CRUD operations on policy rules, publishes rule
// changes to NATS so agents receive them in real time, and collects metrics
// reported by agents.
package main

import (
	"context"
	"encoding/json"
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

func main() {
	db.Init()
	messaging.Init()
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
		Addr:    ":" + getPort(),
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

func getPort() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "8080"
}
