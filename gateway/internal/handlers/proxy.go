package handlers

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// @Summary      List available agents
// @Description  Return all registered agent types from the runtime service.
// @Tags         agents
// @Security     BearerAuth
// @Produce      json
// @Success      200  {array}  map[string]interface{}
// @Failure      502  {object} map[string]string
// @Router       /agents [get]
func (h *Handler) ListAgents(c *gin.Context) { h.proxyGet(c, "/agents") }

// @Summary      List available models
// @Description  Return all supported LLM models from the runtime service.
// @Tags         agents
// @Security     BearerAuth
// @Produce      json
// @Success      200  {array}  map[string]interface{}
// @Failure      502  {object} map[string]string
// @Router       /models [get]
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
