package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prrockzed/agentshield/gateway/internal/metrics"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// @Summary      Trigger red-team run
// @Description  Run all adversarial test cases against every security interceptor.
// @Tags         redteam
// @Security     BearerAuth
// @Produce      json
// @Success      201  {object} map[string]interface{}
// @Failure      502  {object} map[string]string
// @Router       /redteam/run [post]
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
		metrics.RedteamPassRate.Set(summary.PassRate)
		emitRedteamEvent(h, summary.ID, summary.Total, summary.Passed, summary.Failed, summary.PassRate)
		// The red-team runner calls interceptors directly (Python→Python), so
		// individual case decisions never reach InsertEvent. Fetch full results
		// here and increment ThreatsBlockedTotal for each BLOCKED case.
		populateRedteamThreatMetrics(h.securityEngineURL, summary.ID)
	}

	c.Data(http.StatusCreated, "application/json", body)
}

// populateRedteamThreatMetrics fetches the per-case results for a completed
// red-team run and increments ThreatsBlockedTotal for every BLOCKED case.
func populateRedteamThreatMetrics(secEngineURL, runID string) {
	resp, err := http.Get(secEngineURL + "/redteam/results/" + runID)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	var detail struct {
		Results []struct {
			Category string `json:"category"`
			Actual   string `json:"actual"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return
	}

	for _, r := range detail.Results {
		if r.Actual == "BLOCKED" {
			metrics.ThreatsBlockedTotal.With(prometheus.Labels{
				"category": redteamCategoryToThreatCategory(r.Category),
			}).Inc()
		}
	}
}

// redteamCategoryToThreatCategory maps the red-team case category (e.g. "TOOL")
// to the threat category label used by agentshield_threats_blocked_total.
func redteamCategoryToThreatCategory(cat string) string {
	switch strings.ToUpper(cat) {
	case "PROMPT":
		return "prompt_injection"
	case "TOOL":
		return "tool_firewall"
	case "NETWORK":
		return "network"
	case "FILESYSTEM":
		return "filesystem"
	case "BROWSER":
		return "browser"
	case "ANTIVIRUS":
		return "antivirus"
	case "HALLUCINATION":
		return "hallucination"
	case "OUTPUT":
		return "dlp"
	default:
		return strings.ToLower(cat)
	}
}

// @Summary      List red-team runs
// @Description  Return all completed red-team run summaries.
// @Tags         redteam
// @Security     BearerAuth
// @Produce      json
// @Success      200  {array}  map[string]interface{}
// @Failure      502  {object} map[string]string
// @Router       /redteam/results [get]
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

// @Summary      Get red-team run by ID
// @Description  Return detailed per-case results for a single red-team run.
// @Tags         redteam
// @Security     BearerAuth
// @Produce      json
// @Param        id path string true "Red-team run ID"
// @Success      200  {object} map[string]interface{}
// @Failure      404  {object} map[string]string
// @Router       /redteam/results/{id} [get]
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
