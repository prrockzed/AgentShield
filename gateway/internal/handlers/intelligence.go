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
