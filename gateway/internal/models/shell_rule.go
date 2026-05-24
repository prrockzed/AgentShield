package models

import "time"

type ShellRule struct {
	ID        string    `json:"id"`
	Pattern   string    `json:"pattern"`
	Reason    string    `json:"reason"`
	Category  string    `json:"category"`
	Source    string    `json:"source"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateShellRuleRequest struct {
	Pattern  string `json:"pattern"  binding:"required"`
	Reason   string `json:"reason"   binding:"required"`
	Category string `json:"category" binding:"required"`
}
