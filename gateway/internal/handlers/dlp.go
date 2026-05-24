package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// GET /api/policies/dlp?category=&active=true
func (h *Handler) ListDlpPolicies(c *gin.Context) {
	where := "WHERE 1=1"
	args := []any{}
	i := 1

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
	_ = i

	q := fmt.Sprintf(`
		SELECT id, category, pattern, label, action, severity, active, source, created_at
		FROM   dlp_policies %s
		ORDER  BY category, created_at`, where)

	rows, err := h.db.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	policies := []models.DlpPolicy{}
	for rows.Next() {
		var p models.DlpPolicy
		if err := rows.Scan(&p.ID, &p.Category, &p.Pattern, &p.Label, &p.Action,
			&p.Severity, &p.Active, &p.Source, &p.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		policies = append(policies, p)
	}

	c.JSON(http.StatusOK, policies)
}

// POST /api/policies/dlp
func (h *Handler) CreateDlpPolicy(c *gin.Context) {
	var req models.CreateDlpPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Action == "" {
		req.Action = "REDACT"
	}
	if req.Severity == "" {
		req.Severity = "HIGH"
	}

	validAction := map[string]bool{"REDACT": true, "BLOCK": true, "FLAG": true}
	if !validAction[req.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action"})
		return
	}
	if !validSeverity(models.Severity(req.Severity)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
		return
	}

	const q = `
		INSERT INTO dlp_policies (category, pattern, label, action, severity, source)
		VALUES ($1, $2, $3, $4, $5, 'custom')
		RETURNING id, category, pattern, label, action, severity, active, source, created_at`

	var p models.DlpPolicy
	err := h.db.QueryRow(q, req.Category, req.Pattern, req.Label, req.Action, req.Severity).Scan(
		&p.ID, &p.Category, &p.Pattern, &p.Label, &p.Action, &p.Severity, &p.Active, &p.Source, &p.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}

	emitPolicyChange(h, "CREATE", "dlp_policies", p.ID, p.Label)
	c.JSON(http.StatusCreated, p)
}

// PATCH /api/policies/dlp/:id
func (h *Handler) ToggleDlpPolicy(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Active bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const q = `
		UPDATE dlp_policies SET active = $1 WHERE id = $2
		RETURNING id, category, pattern, label, action, severity, active, source, created_at`

	var p models.DlpPolicy
	err := h.db.QueryRow(q, body.Active, id).Scan(
		&p.ID, &p.Category, &p.Pattern, &p.Label, &p.Action, &p.Severity, &p.Active, &p.Source, &p.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}

	emitPolicyChange(h, "TOGGLE", "dlp_policies", p.ID, p.Label)
	c.JSON(http.StatusOK, p)
}

// DELETE /api/policies/dlp/:id
func (h *Handler) DeleteDlpPolicy(c *gin.Context) {
	id := c.Param("id")

	res, err := h.db.Exec(`DELETE FROM dlp_policies WHERE id = $1 AND source = 'custom'`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete seeded rule"})
		return
	}

	emitPolicyChange(h, "DELETE", "dlp_policies", id, "")
	c.Status(http.StatusNoContent)
}
