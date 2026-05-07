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
	log.Println("Connected to NATS!")
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
