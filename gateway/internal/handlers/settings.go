package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prrockzed/agentshield/gateway/internal/models"
)

// @Summary      Get security settings
// @Description  Return the caller's per-user security profile. Auto-creates all-enabled defaults if no row exists.
// @Tags         settings
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object} models.SecuritySettings
// @Failure      500  {object} map[string]string
// @Router       /settings/security [get]
func (h *Handler) GetSecuritySettings(c *gin.Context) {
	userID := c.GetString("user_id")
	s, err := fetchSecuritySettings(h.db, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load settings"})
		return
	}
	c.JSON(http.StatusOK, s)
}

// @Summary      Update security settings
// @Description  Full replace of the caller's security profile via upsert.
// @Tags         settings
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body models.SecuritySettings true "Security settings"
// @Success      200  {object} models.SecuritySettings
// @Failure      400  {object} map[string]string
// @Failure      500  {object} map[string]string
// @Router       /settings/security [put]
func (h *Handler) UpdateSecuritySettings(c *gin.Context) {
	userID := c.GetString("user_id")
	var req models.SecuritySettings
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.UserID = userID
	req.UpdatedAt = time.Now()

	const q = `
		INSERT INTO user_security_settings
			(user_id, prompt_scan, tool_intercept, output_scan, network_intercept,
			 filesystem_intercept, behavioral_alert, hallucination_detection,
			 browser_intercept, code_scan, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (user_id) DO UPDATE SET
			prompt_scan             = EXCLUDED.prompt_scan,
			tool_intercept          = EXCLUDED.tool_intercept,
			output_scan             = EXCLUDED.output_scan,
			network_intercept       = EXCLUDED.network_intercept,
			filesystem_intercept    = EXCLUDED.filesystem_intercept,
			behavioral_alert        = EXCLUDED.behavioral_alert,
			hallucination_detection = EXCLUDED.hallucination_detection,
			browser_intercept       = EXCLUDED.browser_intercept,
			code_scan               = EXCLUDED.code_scan,
			updated_at              = EXCLUDED.updated_at`

	_, err := h.db.Exec(q,
		req.UserID,
		req.PromptScan, req.ToolIntercept, req.OutputScan, req.NetworkIntercept,
		req.FilesystemIntercept, req.BehavioralAlert, req.HallucinationDetection,
		req.BrowserIntercept, req.CodeScan, req.UpdatedAt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save settings"})
		return
	}

	c.JSON(http.StatusOK, req)
}

// fetchSecuritySettings reads the user's security settings from the DB.
// Returns DefaultSecuritySettings (all enabled) on any error or missing row — fail-open.
func fetchSecuritySettings(db *sql.DB, userID string) (models.SecuritySettings, error) {
	const q = `
		SELECT user_id, prompt_scan, tool_intercept, output_scan, network_intercept,
		       filesystem_intercept, behavioral_alert, hallucination_detection,
		       browser_intercept, code_scan, updated_at
		FROM user_security_settings
		WHERE user_id = $1`

	var s models.SecuritySettings
	err := db.QueryRow(q, userID).Scan(
		&s.UserID,
		&s.PromptScan, &s.ToolIntercept, &s.OutputScan, &s.NetworkIntercept,
		&s.FilesystemIntercept, &s.BehavioralAlert, &s.HallucinationDetection,
		&s.BrowserIntercept, &s.CodeScan, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		// Auto-insert defaults so subsequent GETs return a real row.
		defaults := models.DefaultSecuritySettings(userID)
		defaults.UpdatedAt = time.Now()
		db.Exec(
			`INSERT INTO user_security_settings
				(user_id, prompt_scan, tool_intercept, output_scan, network_intercept,
				 filesystem_intercept, behavioral_alert, hallucination_detection,
				 browser_intercept, code_scan, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			 ON CONFLICT DO NOTHING`,
			defaults.UserID,
			defaults.PromptScan, defaults.ToolIntercept, defaults.OutputScan, defaults.NetworkIntercept,
			defaults.FilesystemIntercept, defaults.BehavioralAlert, defaults.HallucinationDetection,
			defaults.BrowserIntercept, defaults.CodeScan, defaults.UpdatedAt,
		)
		return defaults, nil
	}
	if err != nil {
		// Any other DB error — fail-open with defaults.
		return models.DefaultSecuritySettings(userID), nil
	}
	return s, nil
}
