package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// GET /api/intelligence/signatures?category=&severity=&active=true&page=1&limit=50
func (h *Handler) ListSignatures(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset := (page - 1) * limit

	where := "WHERE 1=1"
	args := []any{}
	i := 1

	if cat := c.Query("category"); cat != "" {
		where += fmt.Sprintf(" AND category = $%d", i)
		args = append(args, cat)
		i++
	}
	if sev := c.Query("severity"); sev != "" {
		where += fmt.Sprintf(" AND severity = $%d", i)
		args = append(args, sev)
		i++
	}
	if activeStr := c.DefaultQuery("active", "true"); activeStr != "all" {
		active := activeStr != "false"
		where += fmt.Sprintf(" AND active = $%d", i)
		args = append(args, active)
		i++
	}

	var total int
	if err := h.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM threat_signatures %s`, where), args...).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "count query failed"})
		return
	}

	listArgs := append(args, limit, offset)
	listQ := fmt.Sprintf(`
        SELECT id, category, pattern, pattern_type, severity, description, source, version, active, created_at, updated_at
        FROM threat_signatures %s
        ORDER BY category, severity DESC, created_at DESC
        LIMIT $%d OFFSET $%d`, where, i, i+1)

	rows, err := h.db.Query(listQ, listArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	items := []models.ThreatSignature{}
	for rows.Next() {
		var ts models.ThreatSignature
		if err := rows.Scan(&ts.ID, &ts.Category, &ts.Pattern, &ts.PatternType,
			&ts.Severity, &ts.Description, &ts.Source, &ts.Version, &ts.Active,
			&ts.CreatedAt, &ts.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		items = append(items, ts)
	}
	c.JSON(http.StatusOK, models.ListSignaturesResponse{Total: total, Page: page, PageSize: limit, Items: items})
}

// POST /api/intelligence/signatures
func (h *Handler) CreateSignature(c *gin.Context) {
	var req models.CreateThreatSignatureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.PatternType == "" {
		req.PatternType = "REGEX"
	}
	if req.Severity == "" {
		req.Severity = "HIGH"
	}
	if req.Source == "" {
		req.Source = "custom"
	}

	validPT := map[string]bool{"REGEX": true, "SUBSTRING": true, "SEMANTIC": true}
	if !validPT[req.PatternType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pattern_type"})
		return
	}
	if !validSeverity(models.Severity(req.Severity)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
		return
	}

	const q = `
        INSERT INTO threat_signatures (category, pattern, pattern_type, severity, description, source)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, category, pattern, pattern_type, severity, description, source, version, active, created_at, updated_at`

	var ts models.ThreatSignature
	err := h.db.QueryRow(q, req.Category, req.Pattern, req.PatternType,
		req.Severity, req.Description, req.Source).Scan(
		&ts.ID, &ts.Category, &ts.Pattern, &ts.PatternType,
		&ts.Severity, &ts.Description, &ts.Source, &ts.Version, &ts.Active,
		&ts.CreatedAt, &ts.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}
	c.JSON(http.StatusCreated, ts)
}

// GET /api/intelligence/yara-rules?category=&active=true&page=1&limit=50
func (h *Handler) ListYaraRules(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset := (page - 1) * limit

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

	var total int
	if err := h.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM yara_rules %s`, where), args...).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "count query failed"})
		return
	}

	listArgs := append(args, limit, offset)
	listQ := fmt.Sprintf(`
        SELECT id, name, category, rule_text, severity, description, active, created_at
        FROM yara_rules %s
        ORDER BY category, severity DESC, created_at DESC
        LIMIT $%d OFFSET $%d`, where, i, i+1)

	rows, err := h.db.Query(listQ, listArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	items := []models.YaraRule{}
	for rows.Next() {
		var yr models.YaraRule
		if err := rows.Scan(&yr.ID, &yr.Name, &yr.Category, &yr.RuleText,
			&yr.Severity, &yr.Description, &yr.Active, &yr.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		items = append(items, yr)
	}
	c.JSON(http.StatusOK, models.ListYaraRulesResponse{Total: total, Page: page, PageSize: limit, Items: items})
}

// POST /api/intelligence/yara-rules
func (h *Handler) CreateYaraRule(c *gin.Context) {
	var req models.CreateYaraRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Severity == "" {
		req.Severity = "HIGH"
	}
	if !validSeverity(models.Severity(req.Severity)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
		return
	}

	const q = `
        INSERT INTO yara_rules (name, category, rule_text, severity, description)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, category, rule_text, severity, description, active, created_at`

	var yr models.YaraRule
	err := h.db.QueryRow(q, req.Name, req.Category, req.RuleText,
		req.Severity, req.Description).Scan(
		&yr.ID, &yr.Name, &yr.Category, &yr.RuleText,
		&yr.Severity, &yr.Description, &yr.Active, &yr.CreatedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert failed"})
		return
	}
	c.JSON(http.StatusCreated, yr)
}

// PATCH /api/intelligence/signatures/:id
func (h *Handler) ToggleSignature(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Active bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const q = `
        UPDATE threat_signatures SET active = $1 WHERE id = $2
        RETURNING id, category, pattern, pattern_type, severity, description, source, version, active, created_at, updated_at`

	var ts models.ThreatSignature
	err := h.db.QueryRow(q, body.Active, id).Scan(
		&ts.ID, &ts.Category, &ts.Pattern, &ts.PatternType, &ts.Severity,
		&ts.Description, &ts.Source, &ts.Version, &ts.Active, &ts.CreatedAt, &ts.UpdatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "signature not found"})
		return
	}

	emitPolicyChange(h, "TOGGLE", "threat_signatures", ts.ID, ts.Pattern)
	c.JSON(http.StatusOK, ts)
}

// DELETE /api/intelligence/signatures/:id
func (h *Handler) DeleteSignature(c *gin.Context) {
	id := c.Param("id")

	res, err := h.db.Exec(`DELETE FROM threat_signatures WHERE id = $1 AND source = 'custom'`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete seeded rule"})
		return
	}

	emitPolicyChange(h, "DELETE", "threat_signatures", id, "")
	c.Status(http.StatusNoContent)
}

// PATCH /api/intelligence/yara-rules/:id
func (h *Handler) ToggleYaraRule(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Active bool `json:"active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const q = `
        UPDATE yara_rules SET active = $1 WHERE id = $2
        RETURNING id, name, category, rule_text, severity, description, active, created_at`

	var yr models.YaraRule
	err := h.db.QueryRow(q, body.Active, id).Scan(
		&yr.ID, &yr.Name, &yr.Category, &yr.RuleText, &yr.Severity, &yr.Description, &yr.Active, &yr.CreatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "yara rule not found"})
		return
	}

	emitPolicyChange(h, "TOGGLE", "yara_rules", yr.ID, yr.Name)
	c.JSON(http.StatusOK, yr)
}

// DELETE /api/intelligence/yara-rules/:id
func (h *Handler) DeleteYaraRule(c *gin.Context) {
	id := c.Param("id")

	res, err := h.db.Exec(`DELETE FROM yara_rules WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "yara rule not found"})
		return
	}

	emitPolicyChange(h, "DELETE", "yara_rules", id, "")
	c.Status(http.StatusNoContent)
}

// GET /api/intelligence/stats
func (h *Handler) GetIntelligenceStats(c *gin.Context) {
	const q = `
        SELECT ts.category, COUNT(*) AS match_count
        FROM   security_events se
        JOIN   threat_signatures ts ON ts.id = se.matched_signature_id
        WHERE  se.timestamp > NOW() - INTERVAL '24 hours'
        GROUP  BY ts.category
        ORDER  BY match_count DESC`

	rows, err := h.db.Query(q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stats query failed"})
		return
	}
	defer rows.Close()

	stats := []models.CategoryCount{}
	for rows.Next() {
		var cc models.CategoryCount
		if err := rows.Scan(&cc.Category, &cc.MatchCount); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		stats = append(stats, cc)
	}
	c.JSON(http.StatusOK, models.IntelStatsResponse{WindowHours: 24, Stats: stats})
}
