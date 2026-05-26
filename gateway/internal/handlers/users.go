package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/prrockzed/agentshield/gateway/internal/models"
)

type createUserRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role"     binding:"required"`
}

// @Summary      Create user
// @Description  Create a new user account (admin or viewer). Admin only.
// @Tags         users
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body createUserRequest true "New user details"
// @Success      201  {object} models.User
// @Failure      400  {object} map[string]string
// @Failure      403  {object} map[string]string
// @Failure      409  {object} map[string]string
// @Router       /users [post]
func (h *Handler) CreateUser(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role != models.RoleAdmin && req.Role != models.RoleViewer {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'admin' or 'viewer'"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}

	var user models.User
	err = h.db.QueryRow(
		`INSERT INTO users (email, password_hash, role)
		 VALUES ($1, $2, $3)
		 RETURNING id, email, role, created_at`,
		req.Email, string(hash), req.Role,
	).Scan(&user.ID, &user.Email, &user.Role, &user.CreatedAt)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// @Summary      List users
// @Description  Return all user accounts. Admin only.
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Success      200  {array}  models.User
// @Failure      403  {object} map[string]string
// @Router       /users [get]
func (h *Handler) ListUsers(c *gin.Context) {
	rows, err := h.db.Query(
		`SELECT id, email, role, created_at FROM users ORDER BY created_at`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	users := []models.User{}
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "scan failed"})
			return
		}
		users = append(users, u)
	}

	c.JSON(http.StatusOK, users)
}

// @Summary      Delete user
// @Description  Delete a user by ID. Cannot delete your own account. Admin only.
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Param        id path string true "User ID"
// @Success      204
// @Failure      400  {object} map[string]string
// @Failure      403  {object} map[string]string
// @Failure      404  {object} map[string]string
// @Router       /users/{id} [delete]
func (h *Handler) DeleteUser(c *gin.Context) {
	id := c.Param("id")

	// Prevent self-deletion
	callerID, _ := c.Get("user_id")
	if callerID == id {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete your own account"})
		return
	}

	result, err := h.db.Exec(`DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.Status(http.StatusNoContent)
}
