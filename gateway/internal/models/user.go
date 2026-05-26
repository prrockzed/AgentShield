package models

import "time"

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

type User struct {
	ID           string    `db:"id"            json:"id"`
	Email        string    `db:"email"         json:"email"`
	PasswordHash string    `db:"password_hash" json:"-"`
	Role         string    `db:"role"          json:"role"`
	CreatedAt    time.Time `db:"created_at"    json:"created_at"`
}
