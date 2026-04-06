package main

import (
	"fmt"
	"log"
	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("Starting Policy Server ...")

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	log.Fatal(r.Run(":8080"))
}