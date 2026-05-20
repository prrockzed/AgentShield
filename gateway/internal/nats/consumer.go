package natscons

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	natsio "github.com/nats-io/nats.go"
	"github.com/prrockzed/agentshield/gateway/internal/handlers"
	"github.com/prrockzed/agentshield/gateway/internal/models"
	"github.com/prrockzed/agentshield/gateway/internal/ws"
)

const (
	streamName    = "SECURITY_EVENTS"
	subjectFilter = "agentshield.security.events.>"
	consumerName  = "audit-log-writer"
)

// Consumer wraps a JetStream durable subscription.
type Consumer struct {
	nc  *natsio.Conn
	js  natsio.JetStreamContext
	db  *sql.DB
	hub *ws.Hub
}

// New connects to NATS, creates the stream (idempotent), and returns a Consumer.
func New(natsURL string, db *sql.DB, hub *ws.Hub) (*Consumer, error) {
	nc, err := natsio.Connect(natsURL)
	if err != nil {
		return nil, err
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, err
	}

	// Create stream idempotently: try AddStream; if it fails, verify the stream
	// exists before treating the error as fatal.
	if _, err = js.AddStream(&natsio.StreamConfig{
		Name:      streamName,
		Subjects:  []string{subjectFilter},
		Retention: natsio.LimitsPolicy,
		MaxAge:    24 * time.Hour,
	}); err != nil {
		if _, infoErr := js.StreamInfo(streamName); infoErr != nil {
			nc.Close()
			return nil, err
		}
		log.Printf("nats: stream %q already exists, continuing", streamName)
	}

	return &Consumer{nc: nc, js: js, db: db, hub: hub}, nil
}

// Start subscribes as a durable queue consumer and runs the message loop in a goroutine.
func (c *Consumer) Start() {
	_, err := c.js.QueueSubscribe(
		subjectFilter,
		consumerName,
		c.handleMessage,
		natsio.Durable(consumerName),
		natsio.DeliverAll(),
		natsio.AckExplicit(),
		natsio.ManualAck(),
	)
	if err != nil {
		log.Fatalf("nats: subscribe failed: %v", err)
	}
	log.Println("nats: consumer started")
}

func (c *Consumer) handleMessage(msg *natsio.Msg) {
	var req models.CreateEventRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		log.Printf("nats: unmarshal failed: %v", err)
		_ = msg.Ack()
		return
	}

	evt, err := handlers.InsertEvent(c.db, req)
	if err != nil {
		log.Printf("nats: insert failed: %v", err)
		_ = msg.Ack()
		return
	}

	payload, err := json.Marshal(evt)
	if err != nil {
		log.Printf("nats: marshal failed: %v", err)
		_ = msg.Ack()
		return
	}

	c.hub.Broadcast(payload)
	_ = msg.Ack()
}
