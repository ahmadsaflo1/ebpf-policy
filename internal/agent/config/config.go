package config

import (
	"log"
	"os"
)

type Config struct {
	NatsURL string
	ServerURL string
	AgentID string
	Interface string  // network interface, e.g. "eth0"
}

func Load() *Config {
	cfg := &Config{
		NatsURL:   getEnv("NATS_URL",   "nats://localhost:4222"),
		ServerURL: getEnv("SERVER_URL", "http://localhost:8080"),
		AgentID:   getEnv("AGENT_ID",   "agent-001"),
		Interface: getEnv("INTERFACE",  "eth0"),
	}

	log.Printf("Agent configured: ID=%s Interface=%s\n",
		cfg.AgentID, cfg.Interface)

	return cfg
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}