package models

import (
	"encoding/json"
	"time"
)

type Run struct {
	ID                 string          `json:"id"`
	Task               *string         `json:"task"`
	Status             string          `json:"status"`
	AgentType          string          `json:"agent_type"`
	Model              string          `json:"model"`
	Output             *string         `json:"output"`
	Steps              json.RawMessage `json:"steps"`
	HallucinationScore *float64        `json:"hallucination_score"`
	CreatedAt          time.Time       `json:"created_at"`
}

type SubmitRunRequest struct {
	AgentType string `json:"agent_type" binding:"required"`
	Model     string `json:"model"      binding:"required"`
	Task      string `json:"task"       binding:"required"`
}

// RuntimeExecuteResponse mirrors the runtime's /execute response shape.
type RuntimeExecuteResponse struct {
	RunID              string          `json:"run_id"`
	AgentType          string          `json:"agent_type"`
	Model              string          `json:"model"`
	Output             string          `json:"output"`
	Steps              json.RawMessage `json:"steps"`
	Status             string          `json:"status"`
	HallucinationScore float64         `json:"hallucination_score"`
}
