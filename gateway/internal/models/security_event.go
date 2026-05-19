package models

import "time"

type EventType string

const (
	EventTypePromptScan          EventType = "PROMPT_SCAN"
	EventTypeToolIntercept       EventType = "TOOL_INTERCEPT"
	EventTypeOutputScan          EventType = "OUTPUT_SCAN"
	EventTypeNetworkIntercept    EventType = "NETWORK_INTERCEPT"
	EventTypeFilesystemIntercept EventType = "FILESYSTEM_INTERCEPT"
	EventTypeBehavioralAlert     EventType = "BEHAVIORAL_ALERT"
)

type Decision string

const (
	DecisionAllowed  Decision = "ALLOWED"
	DecisionBlocked  Decision = "BLOCKED"
	DecisionFlagged  Decision = "FLAGGED"
	DecisionRedacted Decision = "REDACTED"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// SecurityEvent maps to the security_events table.
type SecurityEvent struct {
	ID                 string    `json:"id"`
	RunID              *string   `json:"run_id"`
	EventType          EventType `json:"event_type"`
	Source             string    `json:"source"`
	Payload            any       `json:"payload"`
	Decision           Decision  `json:"decision"`
	Reason             *string   `json:"reason"`
	Severity           Severity  `json:"severity"`
	MatchedSignatureID *string   `json:"matched_signature_id"`
	Timestamp          time.Time `json:"timestamp"`
}

// CreateEventRequest is the body for POST /api/events.
type CreateEventRequest struct {
	RunID              *string   `json:"run_id"`
	EventType          EventType `json:"event_type"  binding:"required"`
	Source             string    `json:"source"      binding:"required"`
	Payload            any       `json:"payload"`
	Decision           Decision  `json:"decision"    binding:"required"`
	Reason             *string   `json:"reason"`
	Severity           Severity  `json:"severity"    binding:"required"`
	MatchedSignatureID *string   `json:"matched_signature_id"`
}
