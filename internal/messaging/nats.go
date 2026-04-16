package messaging

import (
	"log"
	"os"

	"github.com/nats-io/nats.go"
)

var NC *nats.Conn

func Init() {
	var err error
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}
	log.Printf("Connecting to NATS at %s ...\n", natsURL)

	NC, err = nats.Connect(natsURL)
	if err != nil {
		log.Fatal("could not connect to NATS:", err)
	}
	log.Println("Connected to NATS!")
}

func Close() {
	if NC != nil {
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
