package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WebSocketEvents upgrades the connection to WebSocket and relays hub broadcasts.
// GET /ws/events
func (h *Handler) WebSocketEvents(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	h.hub.Register(conn)
	defer h.hub.Unregister(conn)
	// Read loop: discard client messages, detect disconnect.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}
