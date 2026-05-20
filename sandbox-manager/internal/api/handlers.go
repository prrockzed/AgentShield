package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/sandbox-manager/internal/sandbox"
)

// Handler holds a reference to the sandbox Manager.
type Handler struct {
	mgr *sandbox.Manager
}

// NewHandler creates a Handler backed by the given Manager.
func NewHandler(mgr *sandbox.Manager) *Handler {
	return &Handler{mgr: mgr}
}

// Create handles POST /sandbox/create — spins up a new sandbox container.
func (h *Handler) Create(c *gin.Context) {
	id, err := h.mgr.Create(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"sandbox_id": id})
}

// execRequest is the JSON body for POST /sandbox/:id/exec.
type execRequest struct {
	Command string `json:"command" binding:"required"`
}

// Exec handles POST /sandbox/:id/exec — runs a shell command in the sandbox.
func (h *Handler) Exec(c *gin.Context) {
	id := c.Param("id")

	var req execRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.mgr.Exec(c.Request.Context(), id, req.Command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Destroy handles DELETE /sandbox/:id — stops and removes the sandbox container.
func (h *Handler) Destroy(c *gin.Context) {
	id := c.Param("id")

	if err := h.mgr.Destroy(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "destroyed"})
}

// Status handles GET /sandbox/:id/status — returns container state.
func (h *Handler) Status(c *gin.Context) {
	id := c.Param("id")

	info, err := h.mgr.Status(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, info)
}

// List handles GET /sandbox — lists all agentshield sandbox container IDs.
func (h *Handler) List(c *gin.Context) {
	ids, err := h.mgr.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sandboxes": ids})
}

// Ensure time import is used (handlers use context timeouts via mgr).
var _ = http.StatusOK
