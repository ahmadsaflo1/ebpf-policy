// Package messaging provides a thin wrapper around the NATS client for
// publish/subscribe messaging between the policy server and agents.
package messaging

import (
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

// NC is the shared NATS connection used by the entire process.
var NC *nats.Conn

// JS is the shared JetStream context used for guaranteed log delivery.
var JS nats.JetStreamContext

// shuttingDown suppresses disconnect/reconnect log noise during a clean shutdown.
var shuttingDown bool

// Init connects to the NATS server at natsURL, falling back to nats.DefaultURL
// when natsURL is empty. Reconnects indefinitely (5 s between attempts).
// Calls log.Fatal on failure.
func Init(natsURL string) {
	var err error
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}

	NC, err = nats.Connect(natsURL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(5*time.Second),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			if shuttingDown {
                return
            }	
			log.Printf("Reconnected to NATS at %s\n", nc.ConnectedUrl())
		}),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if shuttingDown {
                return
            }
			log.Printf("Disconnected from NATS: %v\n", err)
		}), 
	)
	if err != nil {
		log.Fatal("could not connect to NATS:", err)
	}

	JS, err = NC.JetStream()
	if err != nil {
		log.Fatal("could not create JetStream context:", err)
	}

	log.Println("Connected to NATS!")
}

// EnsureStream creates a JetStream stream with the given name and subjects if
// it does not already exist. Safe to call multiple times (idempotent).
func EnsureStream(name string, subjects []string) error {
	_, err := JS.AddStream(&nats.StreamConfig{
		Name:     name,
		Subjects: subjects,
		Storage:  nats.FileStorage,
	})
	if err == nats.ErrStreamNameAlreadyInUse {
		return nil
	}
	return err
}

// JetStreamPublish publishes data to a JetStream subject with guaranteed delivery.
func JetStreamPublish(topic string, data []byte) error {
	_, err := JS.Publish(topic, data)
	return err
}

// JetStreamSubscribe registers handler for every message on topic via JetStream.
// Messages are acknowledged automatically after the handler returns.
func JetStreamSubscribe(topic string, handler func([]byte)) error {
	_, err := JS.Subscribe(topic, func(m *nats.Msg) {
		handler(m.Data)
		m.Ack()
	}, nats.DeliverNew())
	return err
}

// Close marks the connection as intentionally shutting down (suppressing
// reconnect logs) and then drains and closes the NATS connection.
func Close() {
	if NC != nil {
		shuttingDown = true
		NC.Close()
		log.Println("NATS connection closed.")
	}
}

// Publish serialises data and publishes it to the given NATS topic.
func Publish(topic string, data []byte) error {
	return NC.Publish(topic, data)
}

// Subscribe registers handler to be called for every message received on topic.
// handler receives the raw message payload as a byte slice.
func Subscribe(topic string, handler func(msg []byte)) error {
	_, err := NC.Subscribe(topic, func(m *nats.Msg) {
		handler(m.Data)
	})
	return err
}

// Request sends data to topic and waits up to timeout for a reply.
func Request(topic string, data []byte, timeout time.Duration) ([]byte, error) {
	msg, err := NC.Request(topic, data, timeout)
	if err != nil {
		return nil, err
	}
	return msg.Data, nil
}

// RespondToRequests subscribes to topic and calls handler for each incoming
// request, publishing the returned bytes as the reply.
func RespondToRequests(topic string, handler func([]byte) []byte) error {
	_, err := NC.Subscribe(topic, func(m *nats.Msg) {
		if m.Reply == "" {
			return
		}
		NC.Publish(m.Reply, handler(m.Data))
	})
	return err
}
