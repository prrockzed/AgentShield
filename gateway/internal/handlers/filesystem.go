package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// FilesystemPolicy maps to the filesystem_policies table.
type FilesystemPolicy struct {
	ID          string    `json:"id"`
	PathPattern string    `json:"path_pattern"`
	Operation   string    `json:"operation"`
	Decision    string    `json:"decision"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Reason      *string   `json:"reason"`
	Source      string    `json:"source"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateFilesystemPolicyRequest is the body for POST /api/policies/filesystem.
type CreateFilesystemPolicyRequest struct {
	PathPattern string  `json:"path_pattern" binding:"required"`
	Operation   string  `json:"operation"`
	Decision    string  `json:"decision"`
	Severity    string  `json:"severity"`
	Category    string  `json:"category" binding:"required"`
	Reason      *string `json:"reason"`
	Source      string  `json:"source"`
}

// GET /api/policies/filesystem?category=SSH&operation=READ&decision=BLOCKED&active=true
func (h *Handler) GetFilesystemPolicies(c *gin.Context) {
	where := "WHERE 1=1"
	args  := []any{}
	i     := 1

	if cat := c.Query("category"); cat != "" {
		where += fmt.Sprintf(" AND category = $%d", i)
		args = append(args, cat)
		i++
	}
	if op := c.Query("operation"); op != "" {
		where += fmt.Sprintf(" AND operation = $%d", i)
		args = append(args, op)
		i++
	}
	if dec := c.Query("decision"); dec != "" {
		where += fmt.Sprintf(" AND decision = $%d", i)
		args = append(args, dec)
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
        SELECT id, path_pattern, operation, decision, severity,
               category, reason, source, active, created_at
        FROM   filesystem_policies %s
        ORDER  BY category, path_pattern`, where)

	rows, err := h.db.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	policies := []FilesystemPolicy{}
	for rows.Next() {
		var p FilesystemPolicy
		if err := rows.Scan(
			&p.ID, &p.PathPattern, &p.Operation, &p.Decision, &p.Severity,
			&p.Category, &p.Reason, &p.Source, &p.Active, &p.CreatedAt,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		policies = append(policies, p)
	}

	c.JSON(http.StatusOK, policies)
}

// PATCH /api/policies/filesystem/:id
func (h *Handler) ToggleFilesystemPolicy(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Active bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const q = `
        UPDATE filesystem_policies SET active = $1 WHERE id = $2
        RETURNING id, path_pattern, operation, decision, severity,
                  category, reason, source, active, created_at`

	var p FilesystemPolicy
	err := h.db.QueryRow(q, body.Active, id).Scan(
		&p.ID, &p.PathPattern, &p.Operation, &p.Decision, &p.Severity,
		&p.Category, &p.Reason, &p.Source, &p.Active, &p.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}

	emitPolicyChange(h, "TOGGLE", "filesystem_policies", p.ID, p.PathPattern)
	c.JSON(http.StatusOK, p)
}

// DELETE /api/policies/filesystem/:id
func (h *Handler) DeleteFilesystemPolicy(c *gin.Context) {
	id := c.Param("id")

	res, err := h.db.Exec(`DELETE FROM filesystem_policies WHERE id = $1 AND source = 'custom'`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete seeded rule"})
		return
	}

	emitPolicyChange(h, "DELETE", "filesystem_policies", id, "")
	c.Status(http.StatusNoContent)
}

// POST /api/policies/filesystem — add a custom filesystem policy entry.
func (h *Handler) CreateFilesystemPolicy(c *gin.Context) {
	var req CreateFilesystemPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Operation == "" { req.Operation = "ALL" }
	if req.Decision  == "" { req.Decision  = "BLOCKED" }
	if req.Severity  == "" { req.Severity  = "HIGH" }
	if req.Source    == "" { req.Source    = "custom" }

	const q = `
        INSERT INTO filesystem_policies
            (path_pattern, operation, decision, severity, category, reason, source)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, path_pattern, operation, decision, severity,
                  category, reason, source, active, created_at`

	var p FilesystemPolicy
	err := h.db.QueryRow(
		q, req.PathPattern, req.Operation, req.Decision, req.Severity,
		req.Category, req.Reason, req.Source,
	).Scan(
		&p.ID, &p.PathPattern, &p.Operation, &p.Decision, &p.Severity,
		&p.Category, &p.Reason, &p.Source, &p.Active, &p.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}

	c.JSON(http.StatusCreated, p)
}
