package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

type EventsHandler struct {
	DB *sql.DB
}

func NewEventsHandler(db *sql.DB) *EventsHandler {
	return &EventsHandler{DB: db}
}

func (h *EventsHandler) CreateEvent(c *gin.Context) {
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

	var payloadJSON *string
	if req.Payload != nil {
		b, err := json.Marshal(req.Payload)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		s := string(b)
		payloadJSON = &s
	}

	const q = `
		INSERT INTO security_events
			(run_id, event_type, source, payload, decision, reason, severity, matched_signature_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, run_id, event_type, source, payload, decision, reason, severity, matched_signature_id, timestamp`

	row := h.DB.QueryRow(q,
		req.RunID, string(req.EventType), req.Source, payloadJSON,
		string(req.Decision), req.Reason, string(req.Severity), req.MatchedSignatureID,
	)

	evt, err := scanEvent(row.Scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist event"})
		return
	}

	c.JSON(http.StatusCreated, evt)
}

func (h *EventsHandler) ListEvents(c *gin.Context) {
	runID := c.Query("run_id")
	severity := c.Query("severity")

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
	}

	q := fmt.Sprintf(`
		SELECT id, run_id, event_type, source, payload, decision, reason, severity, matched_signature_id, timestamp
		FROM security_events %s
		ORDER BY timestamp DESC LIMIT 500`, where)

	rows, err := h.DB.Query(q, args...)
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
		models.EventTypeNetworkIntercept, models.EventTypeFilesystemIntercept, models.EventTypeBehavioralAlert:
		return true
	}
	return false
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
