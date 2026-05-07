// Package config handles agent configuration, rule fetching, in-memory rule
// storage, and NATS-based rule update subscriptions.
package config

import (
	"log"
	"os"
)

// Config holds the runtime configuration for the enforcement agent.
type Config struct {
	NatsURL   string
	ServerURL string
	AgentID   string
	Interface string
	Env       string
}

// Opts carries flag/CLI overrides. Empty fields fall back to env vars and defaults.
type Opts struct {
	NatsURL   string
	ServerURL string
	AgentID   string
	Interface string
	Env       string
}

// Load builds a Config by merging Opts (highest priority), env vars, and defaults.
func Load(opts Opts) *Config {
	cfg := &Config{
		NatsURL:   pick(opts.NatsURL,   getEnv("NATS_URL",   "nats://localhost:4222")),
		ServerURL: pick(opts.ServerURL, getEnv("SERVER_URL", "http://localhost:8080")),
		AgentID:   pick(opts.AgentID,   getEnv("AGENT_ID",   "agent-001")),
		Interface: pick(opts.Interface, getEnv("INTERFACE",  "eth0")),
		Env:       pick(opts.Env,       getEnv("ENV",        "")),
	}

	log.Printf("Agent configured: ID=%s Interface=%s Env=%s\n",
		cfg.AgentID, cfg.Interface, cfg.Env)

	return cfg
}

// pick returns the first non-empty value.
func pick(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// getEnv returns the env variable value or defaultVal when unset.
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}