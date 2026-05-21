package handlers

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) ListAgents(c *gin.Context) { h.proxyGet(c, "/agents") }
func (h *Handler) ListModels(c *gin.Context) { h.proxyGet(c, "/models") }

func (h *Handler) proxyGet(c *gin.Context, path string) {
	resp, err := http.Get(h.runtimeURL + path)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "runtime unavailable"})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}
