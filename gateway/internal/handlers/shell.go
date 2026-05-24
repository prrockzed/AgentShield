package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// GET /api/policies/shell?category=&active=true
func (h *Handler) ListShellRules(c *gin.Context) {
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
		SELECT id, pattern, reason, category, source, active, created_at
		FROM   shell_rules %s
		ORDER  BY category, created_at DESC`, where)

	rows, err := h.db.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	rules := []models.ShellRule{}
	for rows.Next() {
		var r models.ShellRule
		if err := rows.Scan(&r.ID, &r.Pattern, &r.Reason, &r.Category, &r.Source, &r.Active, &r.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		rules = append(rules, r)
	}

	c.JSON(http.StatusOK, rules)
}

// POST /api/policies/shell
func (h *Handler) CreateShellRule(c *gin.Context) {
	var req models.CreateShellRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const q = `
		INSERT INTO shell_rules (pattern, reason, category, source)
		VALUES ($1, $2, $3, 'custom')
		RETURNING id, pattern, reason, category, source, active, created_at`

	var rule models.ShellRule
	err := h.db.QueryRow(q, req.Pattern, req.Reason, req.Category).Scan(
		&rule.ID, &rule.Pattern, &rule.Reason, &rule.Category, &rule.Source, &rule.Active, &rule.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}

	emitPolicyChange(h, "CREATE", "shell_rules", rule.ID, rule.Pattern)
	c.JSON(http.StatusCreated, rule)
}

// PATCH /api/policies/shell/:id
func (h *Handler) ToggleShellRule(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Active bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const q = `
		UPDATE shell_rules SET active = $1 WHERE id = $2
		RETURNING id, pattern, reason, category, source, active, created_at`

	var rule models.ShellRule
	err := h.db.QueryRow(q, body.Active, id).Scan(
		&rule.ID, &rule.Pattern, &rule.Reason, &rule.Category, &rule.Source, &rule.Active, &rule.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	emitPolicyChange(h, "TOGGLE", "shell_rules", rule.ID, rule.Pattern)
	c.JSON(http.StatusOK, rule)
}

// DELETE /api/policies/shell/:id
func (h *Handler) DeleteShellRule(c *gin.Context) {
	id := c.Param("id")

	res, err := h.db.Exec(`DELETE FROM shell_rules WHERE id = $1 AND source = 'custom'`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete seeded rule"})
		return
	}

	emitPolicyChange(h, "DELETE", "shell_rules", id, "")
	c.Status(http.StatusNoContent)
}
