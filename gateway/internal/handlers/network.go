package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// NetworkPolicy maps to the network_policies table.
type NetworkPolicy struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Domain    string    `json:"domain"`
	Category  string    `json:"category"`
	Reason    *string   `json:"reason"`
	Source    string    `json:"source"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateNetworkPolicyRequest is the body for POST /api/policies/network/allow.
type CreateNetworkPolicyRequest struct {
	Domain   string  `json:"domain"   binding:"required"`
	Category string  `json:"category" binding:"required"`
	Reason   *string `json:"reason"`
	Source   string  `json:"source"`
}

// GET /api/policies/network?type=BLOCKLIST&category=C2&active=true
func (h *Handler) GetNetworkPolicies(c *gin.Context) {
	where := "WHERE 1=1"
	args := []any{}
	i := 1

	if t := c.Query("type"); t != "" {
		where += fmt.Sprintf(" AND type = $%d", i)
		args = append(args, t)
		i++
	}
	if cat := c.Query("category"); cat != "" {
		where += fmt.Sprintf(" AND category = $%d", i)
		args = append(args, cat)
		i++
	}
	if activeStr := c.DefaultQuery("active", "true"); activeStr != "all" {
		active := activeStr != "false"
		where += fmt.Sprintf(" AND active = $%d", i)
		args = append(args, active)
		i++
	}

	q := fmt.Sprintf(`
		SELECT id, type, domain, category, reason, source, active, created_at
		FROM   network_policies %s
		ORDER  BY category, domain`, where)

	rows, err := h.db.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	policies := []NetworkPolicy{}
	for rows.Next() {
		var p NetworkPolicy
		if err := rows.Scan(
			&p.ID, &p.Type, &p.Domain, &p.Category,
			&p.Reason, &p.Source, &p.Active, &p.CreatedAt,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		policies = append(policies, p)
	}

	c.JSON(http.StatusOK, policies)
}

// POST /api/policies/network/allow — adds a domain to the ALLOWLIST.
func (h *Handler) CreateNetworkPolicy(c *gin.Context) {
	var req CreateNetworkPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Source == "" {
		req.Source = "custom"
	}

	const q = `
		INSERT INTO network_policies (type, domain, category, reason, source)
		VALUES ('ALLOWLIST', $1, $2, $3, $4)
		RETURNING id, type, domain, category, reason, source, active, created_at`

	var p NetworkPolicy
	err := h.db.QueryRow(q, req.Domain, req.Category, req.Reason, req.Source).Scan(
		&p.ID, &p.Type, &p.Domain, &p.Category,
		&p.Reason, &p.Source, &p.Active, &p.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}

	c.JSON(http.StatusCreated, p)
}
