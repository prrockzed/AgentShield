package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

// @Summary      Get run hallucination score
// @Description  Return the hallucination score and HALLUCINATION_DETECTION events for the given run.
// @Tags         runs
// @Security     BearerAuth
// @Produce      json
// @Param        id path string true "Run UUID"
// @Success      200  {object} map[string]interface{}
// @Failure      404  {object} map[string]string
// @Router       /runs/{id}/hallucination [get]
func (h *Handler) GetRunHallucination(c *gin.Context) {
	runID := c.Param("id")

	var score *float64
	err := h.db.QueryRow(
		`SELECT hallucination_score FROM agent_runs WHERE id = $1`, runID,
	).Scan(&score)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}

	type alert struct {
		ID        string  `json:"id"`
		EventType string  `json:"event_type"`
		Source    string  `json:"source"`
		Decision  string  `json:"decision"`
		Reason    *string `json:"reason"`
		Severity  string  `json:"severity"`
		Timestamp string  `json:"timestamp"`
	}

	rows, err := h.db.Query(`
		SELECT id, event_type, source, decision, reason, severity, timestamp
		FROM   security_events
		WHERE  run_id = $1 AND event_type = 'HALLUCINATION_DETECTION'
		ORDER  BY timestamp ASC`, runID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	alerts := []alert{}
	for rows.Next() {
		var a alert
		if err := rows.Scan(&a.ID, &a.EventType, &a.Source,
			&a.Decision, &a.Reason, &a.Severity, &a.Timestamp); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		alerts = append(alerts, a)
	}

	c.JSON(http.StatusOK, gin.H{
		"run_id":              runID,
		"hallucination_score": score,
		"alerts":              alerts,
	})
}
