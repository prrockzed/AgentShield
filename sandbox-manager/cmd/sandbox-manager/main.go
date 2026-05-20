package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/sandbox-manager/internal/api"
	"github.com/prrockzed/agentshield/sandbox-manager/internal/sandbox"
)

func main() {
	port := getEnv("SANDBOX_MANAGER_PORT", "8002")

	mgr, err := sandbox.NewManager()
	if err != nil {
		log.Fatalf("failed to create sandbox manager: %v", err)
	}

	h := api.NewHandler(mgr)

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "sandbox-manager"})
	})

	r.POST("/sandbox/create", h.Create)
	r.POST("/sandbox/:id/exec", h.Exec)
	r.DELETE("/sandbox/:id", h.Destroy)
	r.GET("/sandbox/:id/status", h.Status)
	r.GET("/sandbox", h.List)

	log.Printf("sandbox-manager listening on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
