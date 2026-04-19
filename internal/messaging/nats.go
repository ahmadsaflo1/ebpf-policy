package messaging

import (
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

var NC *nats.Conn
var shuttingDown bool

func Init() {
	var err error
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}

	NC, err = nats.Connect(natsURL,
		nats.MaxReconnects(-1), // keep trying to reconnect indefinitely
		nats.ReconnectWait(5 * time.Second), // wait 5 seconds between reconnect attempts
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

func Close() {
	if NC != nil {
		shuttingDown = true
		NC.Close()
		log.Println("NATS connection closed.")
	}
}

// Publish a message to a topic
func Publish(topic string, data []byte) error {
	return NC.Publish(topic, data)
}

// Subscribe to a topic with a handler function that processes incoming messages
func Subscribe(topic string, handler func(msg []byte)) error {
	_, err := NC.Subscribe(topic, func(m *nats.Msg) {
		handler(m.Data)
	})
	return err
}
