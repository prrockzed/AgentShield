package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prrockzed/agentshield/gateway/internal/metrics"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// runtimeClient is a dedicated HTTP client with a long timeout for agent runs.
var runtimeClient = &http.Client{Timeout: 5 * time.Minute}

// @Summary      Submit a new agent run
// @Description  Execute an agent task and persist the result.
// @Tags         runs
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body models.SubmitRunRequest true "Run request"
// @Success      201  {object} map[string]interface{}
// @Failure      400  {object} map[string]string
// @Failure      502  {object} map[string]string
// @Router       /runs [post]
func (h *Handler) SubmitRun(c *gin.Context) {
	var req models.SubmitRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	body, _ := json.Marshal(req)

	metrics.SandboxActiveCount.Inc()
	start := time.Now()
	defer func() {
		metrics.SandboxActiveCount.Dec()
		metrics.RunDurationSeconds.Observe(time.Since(start).Seconds())
	}()

	resp, err := runtimeClient.Post(h.runtimeURL+"/execute", "application/json", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "runtime unavailable"})
		return
	}
	defer resp.Body.Close()

	// Persist blocked run then forward 403.
	if resp.StatusCode == http.StatusForbidden {
		blocked, _ := io.ReadAll(resp.Body)
		var b403 struct {
			Detail string `json:"detail"`
			RunID  string `json:"run_id"`
		}
		if err := json.Unmarshal(blocked, &b403); err == nil && b403.RunID != "" {
			h.db.Exec(
				`INSERT INTO agent_runs (id, task, agent_type, model, status, output, steps)
				 VALUES ($1, $2, $3, $4, 'blocked', $5, '[]')
				 ON CONFLICT (id) DO NOTHING`,
				b403.RunID, req.Task, req.AgentType, req.Model, b403.Detail,
			)
		}
		metrics.RunsTotal.With(prometheus.Labels{
			"status": "blocked", "agent_type": req.AgentType,
		}).Inc()
		c.Data(http.StatusForbidden, "application/json", blocked)
		return
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		errBody, _ := io.ReadAll(resp.Body)
		c.Data(resp.StatusCode, "application/json", errBody)
		return
	}

	var rr models.RuntimeExecuteResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode runtime response"})
		return
	}

	const q = `
		INSERT INTO agent_runs (id, task, agent_type, model, status, output, steps, hallucination_score)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE
		  SET task = EXCLUDED.task, status = EXCLUDED.status,
		      output = EXCLUDED.output, steps = EXCLUDED.steps,
		      hallucination_score = EXCLUDED.hallucination_score
		RETURNING id, task, status, agent_type, model, output, steps, hallucination_score, created_at`

	stepsJSON := rr.Steps
	if len(stepsJSON) == 0 {
		stepsJSON = json.RawMessage("[]")
	}

	row := h.db.QueryRow(q, rr.RunID, req.Task, rr.AgentType, rr.Model, rr.Status, rr.Output, []byte(stepsJSON), rr.HallucinationScore)
	run, err := scanRun(row.Scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist run"})
		return
	}

	metrics.RunsTotal.With(prometheus.Labels{
		"status": rr.Status, "agent_type": rr.AgentType,
	}).Inc()

	c.JSON(http.StatusCreated, run)
}

// @Summary      List agent runs
// @Description  Return the 100 most recent agent runs.
// @Tags         runs
// @Security     BearerAuth
// @Produce      json
// @Success      200  {array}  map[string]interface{}
// @Failure      500  {object} map[string]string
// @Router       /runs [get]
func (h *Handler) ListRuns(c *gin.Context) {
	const q = `
		SELECT id, task, status, agent_type, model, output, steps, hallucination_score, created_at
		FROM agent_runs ORDER BY created_at DESC LIMIT 100`

	rows, err := h.db.Query(q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	runs := []models.Run{}
	for rows.Next() {
		run, err := scanRun(rows.Scan)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		runs = append(runs, run)
	}

	c.JSON(http.StatusOK, runs)
}

// @Summary      Get agent run by ID
// @Description  Return a single agent run by its UUID.
// @Tags         runs
// @Security     BearerAuth
// @Produce      json
// @Param        id path string true "Run UUID"
// @Success      200  {object} map[string]interface{}
// @Failure      404  {object} map[string]string
// @Router       /runs/{id} [get]
func (h *Handler) GetRun(c *gin.Context) {
	id := c.Param("id")

	const q = `
		SELECT id, task, status, agent_type, model, output, steps, hallucination_score, created_at
		FROM agent_runs WHERE id = $1`

	row := h.db.QueryRow(q, id)
	run, err := scanRun(row.Scan)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
		return
	}

	c.JSON(http.StatusOK, run)
}

func scanRun(scan func(...any) error) (models.Run, error) {
	var run models.Run
	var stepsRaw []byte
	err := scan(
		&run.ID, &run.Task, &run.Status, &run.AgentType, &run.Model,
		&run.Output, &stepsRaw, &run.HallucinationScore, &run.CreatedAt,
	)
	if err != nil {
		return run, err
	}
	if len(stepsRaw) > 0 {
		run.Steps = json.RawMessage(stepsRaw)
	} else {
		run.Steps = json.RawMessage("[]")
	}
	return run, nil
}
