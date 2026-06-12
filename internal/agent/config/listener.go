package config

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// RuleHandler is called whenever a policy rule is created or updated.
type RuleHandler func(rule models.PolicyRule)

// DeleteHandler is called whenever a policy rule is deleted.
// The argument is the ID of the deleted rule.
type DeleteHandler func(ruleID int)

// WhitelistHandler is called whenever the autonomous classifier adds or removes
// an IP from the eBPF bypass list. action is "add" or "remove".
type WhitelistHandler func(update models.WhitelistUpdate)

// Listener subscribes to NATS topics and dispatches incoming rule changes
// to the provided RuleHandler and DeleteHandler callbacks.
type Listener struct {
	onUpdate    RuleHandler
	onDelete    DeleteHandler
	onWhitelist WhitelistHandler
}

// NewListener constructs a Listener that will call onUpdate for create/update
// events and onDelete for delete events.
func NewListener(onUpdate RuleHandler, onDelete DeleteHandler) *Listener {
	return &Listener{
		onUpdate: onUpdate,
		onDelete: onDelete,
	}
}

// SetWhitelistHandler registers the callback that handles whitelist.update
// messages from the classifier. Must be called before Start.
func (l *Listener) SetWhitelistHandler(h WhitelistHandler) {
	l.onWhitelist = h
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

	// Subscribe to classifier whitelist updates so agents apply them directly
	// in their eBPF bypass_list map without an agent restart.
	if l.onWhitelist != nil {
		err := messaging.Subscribe("whitelist.update", func(data []byte) {
			var update models.WhitelistUpdate
			if err := json.Unmarshal(data, &update); err != nil {
				log.Printf("Failed to unmarshal whitelist.update: %v\n", err)
				return
			}
			l.onWhitelist(update)
		})
		if err != nil {
			return fmt.Errorf("whitelist.update subscribe: %w", err)
		}
	}

	return nil
}
