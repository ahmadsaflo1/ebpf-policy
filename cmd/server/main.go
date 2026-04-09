package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/api"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database and NATS
	db.Init()
	messaging.Init()
	defer messaging.Close()

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	rules := r.Group("/api/rules")
	{
		rules.GET("", api.GetRules)
		rules.POST("", api.CreateRule)
		rules.GET("/:id", api.GetRule)
		rules.PUT("/:id", api.UpdateRule)
		rules.DELETE("/:id", api.DeleteRule)
	}

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	go func() {
		log.Println("Starting server on :8080 ...")
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
