package messaging

import (
	"log"
	"github.com/nats-io/nats.go"
)

var NC *nats.Conn

func Init() {
	var err error
	NC, err = nats.Connect(nats.DefaultURL)
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