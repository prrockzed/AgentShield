package ws

import (
	"sync"

	"github.com/gorilla/websocket"
)

// Hub tracks all live WebSocket connections and broadcasts messages to them.
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
}

// NewHub creates a new Hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[*websocket.Conn]struct{})}
}

// Register adds a connection to the hub.
func (h *Hub) Register(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[conn] = struct{}{}
}

// Unregister removes a connection and closes it.
func (h *Hub) Unregister(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, conn)
	conn.Close()
}

// Broadcast sends a JSON payload to all registered connections.
// Broken connections are removed automatically.
func (h *Hub) Broadcast(msg []byte) {
	h.mu.RLock()
	conns := make([]*websocket.Conn, 0, len(h.clients))
	for conn := range h.clients {
		conns = append(conns, conn)
	}
	h.mu.RUnlock()

	var broken []*websocket.Conn
	for _, conn := range conns {
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			broken = append(broken, conn)
		}
	}

	if len(broken) > 0 {
		h.mu.Lock()
		for _, conn := range broken {
			delete(h.clients, conn)
			conn.Close()
		}
		h.mu.Unlock()
	}
}
