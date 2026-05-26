package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireAdmin aborts with 403 if the authenticated user does not have the admin role.
// Must be used after RequireAuth so that "userRole" is already set in the gin context.
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("userRole")
		if role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin role required"})
			return
		}
		c.Next()
	}
}
