package models

import "time"

type YaraRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	RuleText    string    `json:"rule_text"`
	Severity    string    `json:"severity"`
	Description *string   `json:"description"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateYaraRuleRequest struct {
	Name        string  `json:"name"      binding:"required"`
	Category    string  `json:"category"  binding:"required"`
	RuleText    string  `json:"rule_text" binding:"required"`
	Severity    string  `json:"severity"`
	Description *string `json:"description"`
}

type ListYaraRulesResponse struct {
	Total    int        `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Items    []YaraRule `json:"items"`
}
