package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/prrockzed/agentshield/gateway/internal/auth"
)

type loginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// @Summary      Login
// @Description  Authenticate with email and password, receive JWT tokens.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body loginRequest true "Login credentials"
// @Success      200  {object} tokenResponse
// @Failure      400  {object} map[string]string
// @Failure      401  {object} map[string]string
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var id, hash, role string
	err := h.db.QueryRow(`SELECT id, password_hash, role FROM users WHERE email = $1`, req.Email).
		Scan(&id, &hash, &role)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	access, err := auth.IssueAccessToken(id, req.Email, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	refresh, err := auth.IssueRefreshToken(id, req.Email, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken: access, RefreshToken: refresh,
		TokenType: "Bearer", ExpiresIn: int(auth.AccessTokenTTL.Seconds()),
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// @Summary      Refresh tokens
// @Description  Exchange a valid refresh token for a new access/refresh token pair.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body refreshRequest true "Refresh token"
// @Success      200  {object} tokenResponse
// @Failure      400  {object} map[string]string
// @Failure      401  {object} map[string]string
// @Router       /auth/refresh [post]
func (h *Handler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	claims, err := auth.ParseToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	// Re-fetch role from DB so role changes take effect on token refresh
	var role string
	if dbErr := h.db.QueryRow(`SELECT role FROM users WHERE id = $1`, claims.Subject).Scan(&role); dbErr != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	access, err := auth.IssueAccessToken(claims.Subject, claims.Email, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	newRefresh, err := auth.IssueRefreshToken(claims.Subject, claims.Email, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken: access, RefreshToken: newRefresh,
		TokenType: "Bearer", ExpiresIn: int(auth.AccessTokenTTL.Seconds()),
	})
}
