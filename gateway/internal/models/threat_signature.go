package models

import "time"

type ThreatSignature struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"`
	Severity    string    `json:"severity"`
	Description *string   `json:"description"`
	Source      string    `json:"source"`
	Version     int       `json:"version"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateThreatSignatureRequest struct {
	Category    string  `json:"category"     binding:"required"`
	Pattern     string  `json:"pattern"      binding:"required"`
	PatternType string  `json:"pattern_type"` // REGEX | SUBSTRING | SEMANTIC; default REGEX
	Severity    string  `json:"severity"`     // default HIGH
	Description *string `json:"description"`
	Source      string  `json:"source"` // default custom
}

type ListSignaturesResponse struct {
	Total    int               `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
	Items    []ThreatSignature `json:"items"`
}

type IntelStatsResponse struct {
	WindowHours int             `json:"window_hours"`
	Stats       []CategoryCount `json:"stats"`
}

type CategoryCount struct {
	Category   string `json:"category"`
	MatchCount int    `json:"match_count"`
}
