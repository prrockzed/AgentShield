package models

import "time"

type DlpPolicy struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	Pattern   string    `json:"pattern"`
	Label     string    `json:"label"`
	Action    string    `json:"action"`
	Severity  string    `json:"severity"`
	Active    bool      `json:"active"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateDlpPolicyRequest struct {
	Category string `json:"category" binding:"required"`
	Pattern  string `json:"pattern"  binding:"required"`
	Label    string `json:"label"    binding:"required"`
	Action   string `json:"action"`   // default REDACT
	Severity string `json:"severity"` // default HIGH
}
