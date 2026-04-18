package config

import (
	"encoding/json"
	"log"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

type RuleHandler func(rule models.PolicyRule)
type DeleteHandler func(ruleID int)

type Listener struct {
	onUpdate RuleHandler
	onDelete DeleteHandler
}

func NewListener(onUpdate RuleHandler, onDelete DeleteHandler) *Listener {
	return &Listener{
		onUpdate: onUpdate,
		onDelete: onDelete,
	}
}

// Start listening for policy updates and deletions. If env is specified, also listen for updates specific to that env (e.g. "production").
func (l *Listener) Start(env string) error {
	// Build list of topics to subscribe to
    topics := []string{"policy.update"}
    if env != "" {
        topics = append(topics, "policy.update."+env)
    }

    // Subscribe to all topics using the same handler
    for _, topic := range topics {
        t := topic // avoid closure capture issue
        err := messaging.Subscribe(t, func(data []byte) {
            var rule models.PolicyRule
            if err := json.Unmarshal(data, &rule); err != nil {
                log.Printf("Failed to unmarshal policy update on topic %s: %v\n", t, err)
                return
            }
            log.Printf("Received policy update on topic '%s': %s\n", t, rule.Name)
            l.onUpdate(rule)
        })
        if err != nil {
            return err
        }
    }

    // Listen for policy deletions
    err := messaging.Subscribe("policy.delete", func(data []byte) {
        var payload map[string]int
        if err := json.Unmarshal(data, &payload); err != nil {
            log.Println("Failed to unmarshal policy delete:", err)
            return
        }
        ruleID := payload["id"]
        log.Printf("Received policy delete for ID: %d\n", ruleID)
        l.onDelete(ruleID)
    })
    return err
}