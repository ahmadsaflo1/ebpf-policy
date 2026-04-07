package main

import (
	"log"
	"github.com/gin-gonic/gin"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/api"
    "github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

func main() {
	db.Init()

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	rules := r.Group("/api/rules")
    {
        rules.GET("",      api.GetRules)
        rules.POST("",     api.CreateRule)
        rules.GET("/:id",  api.GetRule)
        rules.PUT("/:id",  api.UpdateRule)
        rules.DELETE("/:id", api.DeleteRule)
    }

	log.Println("Server run on :8080")
	log.Fatal(r.Run(":8080"))
}