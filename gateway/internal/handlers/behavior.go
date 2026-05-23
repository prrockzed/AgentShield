package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// GET /api/runs/:id/behavior
// Returns all BEHAVIORAL_ALERT security events for the given run, ordered chronologically.
func (h *Handler) GetRunBehavior(c *gin.Context) {
	runID := c.Param("id")

	const q = `
        SELECT id, run_id, event_type, source, payload, decision, reason, severity,
               matched_signature_id, timestamp
        FROM   security_events
        WHERE  run_id = $1 AND event_type = $2
        ORDER  BY timestamp ASC`

	rows, err := h.db.Query(q, runID, string(models.EventTypeBehavioralAlert))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	events := []models.SecurityEvent{}
	for rows.Next() {
		evt, err := scanEvent(rows.Scan)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		events = append(events, evt)
	}

	c.JSON(http.StatusOK, gin.H{
		"run_id": runID,
		"alerts": events,
	})
}
