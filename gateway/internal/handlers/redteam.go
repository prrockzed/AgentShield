package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// TriggerRedteamRun proxies POST /api/redteam/run to the security engine,
// emits a RED_TEAM_RUN security event, and returns 201 with the engine's body.
func (h *Handler) TriggerRedteamRun(c *gin.Context) {
	resp, err := http.Post(h.securityEngineURL+"/redteam/run", "application/json", nil)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "security engine unreachable"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read engine response"})
		return
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		c.Data(resp.StatusCode, "application/json", body)
		return
	}

	// Decode summary fields to emit event
	var summary struct {
		ID       string  `json:"id"`
		Total    int     `json:"total"`
		Passed   int     `json:"passed"`
		Failed   int     `json:"failed"`
		PassRate float64 `json:"pass_rate"`
	}
	if err := json.Unmarshal(body, &summary); err == nil {
		emitRedteamEvent(h, summary.ID, summary.Total, summary.Passed, summary.Failed, summary.PassRate)
	}

	c.Data(http.StatusCreated, "application/json", body)
}

// ListRedteamRuns proxies GET /api/redteam/results to the security engine.
func (h *Handler) ListRedteamRuns(c *gin.Context) {
	resp, err := http.Get(h.securityEngineURL + "/redteam/results")
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "security engine unreachable"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read engine response"})
		return
	}

	c.Data(resp.StatusCode, "application/json", body)
}

// GetRedteamRun proxies GET /api/redteam/results/:id to the security engine,
// mirroring 404 if the engine returns 404.
func (h *Handler) GetRedteamRun(c *gin.Context) {
	id := c.Param("id")

	resp, err := http.Get(h.securityEngineURL + "/redteam/results/" + id)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "security engine unreachable"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read engine response"})
		return
	}

	c.Data(resp.StatusCode, "application/json", body)
}

// emitRedteamEvent persists a RED_TEAM_RUN event and broadcasts it over the WebSocket hub.
func emitRedteamEvent(h *Handler, runID string, total, passed, failed int, passRate float64) {
	req := models.CreateEventRequest{
		EventType: models.EventTypeRedTeamRun,
		Source:    "redteam_engine",
		Payload: map[string]any{
			"run_id":    runID,
			"total":     total,
			"passed":    passed,
			"failed":    failed,
			"pass_rate": passRate,
		},
		Decision: models.DecisionAllowed,
		Severity: models.SeverityInfo,
	}
	evt, err := InsertEvent(h.db, req)
	if err != nil {
		return
	}
	if b, err := json.Marshal(evt); err == nil {
		h.hub.Broadcast(b)
	}
}
