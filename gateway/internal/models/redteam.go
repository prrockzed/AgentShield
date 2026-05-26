package models

import "time"

type RedteamRun struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Total      int       `json:"total"`
	Passed     int       `json:"passed"`
	Failed     int       `json:"failed"`
	PassRate   float64   `json:"pass_rate"`
	CreatedAt  time.Time `json:"created_at"`
}
