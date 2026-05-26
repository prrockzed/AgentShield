package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/prrockzed/agentshield/gateway/internal/auth"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// @Summary      WebSocket event stream
// @Description  Upgrade to a WebSocket connection and receive live security events. Pass JWT via ?token= query parameter.
// @Tags         events
// @Param        token query string true "JWT access token"
// @Success      101
// @Failure      401  {object} map[string]string
// @Router       /ws/events [get]
func (h *Handler) WebSocketEvents(c *gin.Context) {
	tokenStr := c.Query("token")
	if tokenStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}
	if _, err := auth.ParseToken(tokenStr); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	h.hub.Register(conn)
	defer h.hub.Unregister(conn)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}
