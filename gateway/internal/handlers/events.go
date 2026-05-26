package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prrockzed/agentshield/gateway/internal/metrics"
	"github.com/prrockzed/agentshield/gateway/internal/models"
	"github.com/prrockzed/agentshield/gateway/internal/ws"
)

// Handler holds shared dependencies for all HTTP and WebSocket handlers.
type Handler struct {
	db                 *sql.DB
	hub                *ws.Hub
	runtimeURL         string
	securityEngineURL  string
}

// NewHandler creates a Handler wired to the given DB, WebSocket hub, runtime URL, and security engine URL.
func NewHandler(db *sql.DB, hub *ws.Hub, runtimeURL, securityEngineURL string) *Handler {
	return &Handler{db: db, hub: hub, runtimeURL: runtimeURL, securityEngineURL: securityEngineURL}
}

// InsertEvent persists a security event to PostgreSQL and returns the created record.
func InsertEvent(db *sql.DB, req models.CreateEventRequest) (models.SecurityEvent, error) {
	var payloadJSON *string
	if req.Payload != nil {
		b, err := json.Marshal(req.Payload)
		if err != nil {
			return models.SecurityEvent{}, err
		}
		s := string(b)
		payloadJSON = &s
	}

	const q = `
		INSERT INTO security_events
			(run_id, event_type, source, payload, decision, reason, severity, matched_signature_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, run_id, event_type, source, payload, decision, reason, severity, matched_signature_id, timestamp`

	row := db.QueryRow(q,
		req.RunID, string(req.EventType), req.Source, payloadJSON,
		string(req.Decision), req.Reason, string(req.Severity), req.MatchedSignatureID,
	)

	evt, err := scanEvent(row.Scan)
	if err != nil {
		return evt, err
	}

	// Always: security event counter
	metrics.SecurityEventsTotal.With(prometheus.Labels{
		"event_type": string(req.EventType),
		"decision":   string(req.Decision),
		"severity":   string(req.Severity),
	}).Inc()

	// If BLOCKED: threats blocked by category
	if req.Decision == models.DecisionBlocked {
		metrics.ThreatsBlockedTotal.With(prometheus.Labels{
			"category": eventTypeToCategory(string(req.EventType)),
		}).Inc()
	}

	// If PROMPT_SCAN: observe injection score from payload
	if req.EventType == models.EventTypePromptScan {
		if m, ok := req.Payload.(map[string]any); ok {
			if score, ok := m["score"].(float64); ok {
				metrics.PromptInjectionScore.Observe(score)
			}
		}
	}

	// If OUTPUT_SCAN + REDACTED: count DLP detections by type
	if req.EventType == models.EventTypeOutputScan && req.Decision == models.DecisionRedacted {
		if m, ok := req.Payload.(map[string]any); ok {
			if dets, ok := m["detections"].([]any); ok {
				for _, d := range dets {
					if dm, ok := d.(map[string]any); ok {
						if cat, ok := dm["category"].(string); ok && cat != "" {
							metrics.DlpDetectionsTotal.With(prometheus.Labels{"type": cat}).Inc()
						}
					}
				}
			}
		}
	}

	return evt, nil
}

func eventTypeToCategory(et string) string {
	switch et {
	case "PROMPT_SCAN":
		return "prompt_injection"
	case "TOOL_INTERCEPT":
		return "tool_firewall"
	case "NETWORK_INTERCEPT":
		return "network"
	case "FILESYSTEM_INTERCEPT":
		return "filesystem"
	case "BROWSER_INTERCEPT":
		return "browser"
	case "CODE_SCAN":
		return "antivirus"
	case "HALLUCINATION_DETECTION":
		return "hallucination"
	case "OUTPUT_SCAN":
		return "dlp"
	default:
		return "other"
	}
}

// @Summary      Create security event
// @Description  Persist a new security event emitted by an interceptor.
// @Tags         events
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body models.CreateEventRequest true "Event payload"
// @Success      201  {object} models.SecurityEvent
// @Failure      400  {object} map[string]string
// @Router       /events [post]
func (h *Handler) CreateEvent(c *gin.Context) {
	var req models.CreateEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !validEventType(req.EventType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event_type"})
		return
	}
	if !validDecision(req.Decision) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid decision"})
		return
	}
	if !validSeverity(req.Severity) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
		return
	}

	evt, err := InsertEvent(h.db, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist event"})
		return
	}

	c.JSON(http.StatusCreated, evt)
}

// @Summary      List security events
// @Description  Return up to 500 security events, optionally filtered.
// @Tags         events
// @Security     BearerAuth
// @Produce      json
// @Param        run_id     query  string false "Filter by run ID"
// @Param        severity   query  string false "Filter by severity"
// @Param        event_type query  string false "Filter by event type"
// @Param        decision   query  string false "Filter by decision"
// @Success      200  {array}  models.SecurityEvent
// @Failure      500  {object} map[string]string
// @Router       /events [get]
func (h *Handler) ListEvents(c *gin.Context) {
	runID     := c.Query("run_id")
	severity  := c.Query("severity")
	eventType := c.Query("event_type")
	decision  := c.Query("decision")

	where := "WHERE 1=1"
	args := []any{}
	i := 1

	if runID != "" {
		where += fmt.Sprintf(" AND run_id = $%d", i)
		args = append(args, runID)
		i++
	}
	if severity != "" {
		where += fmt.Sprintf(" AND severity = $%d", i)
		args = append(args, severity)
		i++
	}
	if eventType != "" {
		where += fmt.Sprintf(" AND event_type = $%d", i)
		args = append(args, eventType)
		i++
	}
	if decision != "" {
		where += fmt.Sprintf(" AND decision = $%d", i)
		args = append(args, decision)
		i++
	}
	_ = i

	q := fmt.Sprintf(`
		SELECT id, run_id, event_type, source, payload, decision, reason, severity, matched_signature_id, timestamp
		FROM security_events %s
		ORDER BY timestamp DESC LIMIT 500`, where)

	rows, err := h.db.Query(q, args...)
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

	c.JSON(http.StatusOK, events)
}

// scanEvent is a shared scan helper that works for both QueryRow and Rows.
func scanEvent(scan func(...any) error) (models.SecurityEvent, error) {
	var evt models.SecurityEvent
	var payloadRaw []byte
	err := scan(
		&evt.ID, &evt.RunID, &evt.EventType, &evt.Source, &payloadRaw,
		&evt.Decision, &evt.Reason, &evt.Severity, &evt.MatchedSignatureID, &evt.Timestamp,
	)
	if err != nil {
		return evt, err
	}
	if len(payloadRaw) > 0 {
		_ = json.Unmarshal(payloadRaw, &evt.Payload)
	}
	return evt, nil
}

func validEventType(v models.EventType) bool {
	switch v {
	case models.EventTypePromptScan, models.EventTypeToolIntercept, models.EventTypeOutputScan,
		models.EventTypeNetworkIntercept, models.EventTypeFilesystemIntercept, models.EventTypeBehavioralAlert,
		models.EventTypeHallucinationDetection, models.EventTypeBrowserIntercept, models.EventTypeCodeScan,
		models.EventTypePolicyChange, models.EventTypeRedTeamRun:
		return true
	}
	return false
}

// emitPolicyChange persists a POLICY_CHANGE event and broadcasts it over the WebSocket hub.
func emitPolicyChange(h *Handler, action, table, recordID, detail string) {
	req := models.CreateEventRequest{
		EventType: models.EventTypePolicyChange,
		Source:    "policy_manager",
		Payload:   map[string]any{"action": action, "table": table, "id": recordID, "detail": detail},
		Decision:  models.DecisionAllowed,
		Severity:  models.SeverityInfo,
	}
	evt, err := InsertEvent(h.db, req)
	if err != nil {
		return
	}
	if b, err := json.Marshal(evt); err == nil {
		h.hub.Broadcast(b)
	}
}

func validDecision(v models.Decision) bool {
	switch v {
	case models.DecisionAllowed, models.DecisionBlocked, models.DecisionFlagged, models.DecisionRedacted:
		return true
	}
	return false
}

func validSeverity(v models.Severity) bool {
	switch v {
	case models.SeverityInfo, models.SeverityLow, models.SeverityMedium, models.SeverityHigh, models.SeverityCritical:
		return true
	}
	return false
}
