// Package config handles agent configuration, rule fetching, in-memory rule
// storage, and NATS-based rule update subscriptions.
package config

import (
	"log"
	"os"
)

// Config holds the runtime configuration for the enforcement agent.
// All fields are read from environment variables with sensible defaults.
type Config struct {
	NatsURL   string // NATS broker address (NATS_URL)
	ServerURL string // Policy server base URL (SERVER_URL)
	AgentID   string // Unique identifier for this agent (AGENT_ID)
	Interface string // Network interface to attach eBPF to, e.g. "eth0" (INTERFACE)
	Env       string // Environment tag, e.g. "production" (ENV); empty means global
}

// Load reads agent configuration from environment variables and returns a
// populated Config. Defaults are applied for any variable that is not set.
func Load() *Config {
	cfg := &Config{
		NatsURL:   getEnv("NATS_URL",   "nats://localhost:4222"),
		ServerURL: getEnv("SERVER_URL", "http://localhost:8080"),
		AgentID:   getEnv("AGENT_ID",   "agent-001"),
		Interface: getEnv("INTERFACE",  "eth0"),
		Env:       getEnv("ENV",       ""),
	}

	log.Printf("Agent configured: ID=%s Interface=%s Env=%s\n",
		cfg.AgentID, cfg.Interface, cfg.Env)

	return cfg
}

// getEnv returns the value of the environment variable key, or defaultVal if
// the variable is not set or is empty.
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}