package config

import (
	"encoding/json"
	"log"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// RuleHandler is called whenever a policy rule is created or updated.
type RuleHandler func(rule models.PolicyRule)

// DeleteHandler is called whenever a policy rule is deleted.
// The argument is the ID of the deleted rule.
type DeleteHandler func(ruleID int)

// Listener subscribes to NATS topics and dispatches incoming rule changes
// to the provided RuleHandler and DeleteHandler callbacks.
type Listener struct {
	onUpdate RuleHandler
	onDelete DeleteHandler
}

// NewListener constructs a Listener that will call onUpdate for create/update
// events and onDelete for delete events.
func NewListener(onUpdate RuleHandler, onDelete DeleteHandler) *Listener {
	return &Listener{
		onUpdate: onUpdate,
		onDelete: onDelete,
	}
}

// Start subscribes to NATS policy topics and begins dispatching events.
// It always subscribes to the global "policy.update" and "policy.delete"
// topics; when env is non-empty it additionally subscribes to the
// environment-scoped variants (e.g. "policy.update.production").
func (l *Listener) Start(env string) error {
	topics := []string{"policy.update"}
	if env != "" {
		topics = append(topics, "policy.update."+env)
	}

	for _, topic := range topics {
        t := topic // avoid closure capture issue
        err := messaging.Subscribe(t, func(data []byte) {
            var rule models.PolicyRule
            if err := json.Unmarshal(data, &rule); err != nil {
                log.Printf("Failed to unmarshal policy update on topic %s: %v\n", t, err)
                return
            }
            l.onUpdate(rule)
        })
        if err != nil {
            return err
        }
    }

	deleteTopics := []string{"policy.delete"}
    if env != "" {
        deleteTopics = append(deleteTopics, "policy.delete."+env)
    }

    for _, topic := range deleteTopics {
        t := topic
        err := messaging.Subscribe(t, func(data []byte) {
            var payload map[string]int
            if err := json.Unmarshal(data, &payload); err != nil {
                log.Printf("Failed to unmarshal policy delete on topic %s: %v\n", t, err)
                return
            }
            ruleID := payload["id"]
            l.onDelete(ruleID)
        })
        if err != nil {
            return err
        }
    }

    return nil
}