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
// It always subscribes to the global subject and a per-agent subject
// (policy.update.<agentID>) so that targeted rules reach only this agent.
// When topic is set, it also subscribes to the topic-scoped subject.
func (l *Listener) Start(agentID, topic string) error {
	var updateTopics, deleteTopics []string

	if topic == "" {
		updateTopics = []string{"policy.update", "policy.update.>"}
		deleteTopics = []string{"policy.delete", "policy.delete.>"}
	} else {
		updateTopics = []string{"policy.update", "policy.update." + topic, "policy.update." + agentID}
		deleteTopics = []string{"policy.delete", "policy.delete." + topic, "policy.delete." + agentID}
	}

	for _, t := range updateTopics {
		t := t
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

	for _, t := range deleteTopics {
		t := t
		err := messaging.Subscribe(t, func(data []byte) {
			var payload map[string]int
			if err := json.Unmarshal(data, &payload); err != nil {
				log.Printf("Failed to unmarshal policy delete on topic %s: %v\n", t, err)
				return
			}
			l.onDelete(payload["id"])
		})
		if err != nil {
			return err
		}
	}

	return nil
}
