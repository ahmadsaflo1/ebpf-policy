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

// Start begins listening for policy updates from server via NATS.
func (l *Listener) Start() error {
	// listen for new/updates policy
	err := messaging.Subscribe("policy.update", func(data []byte) {
		var rule models.PolicyRule
		if err := json.Unmarshal(data, &rule); err != nil {
			log.Println("Failed to unmarshal policy update:", err)
			return
		}
		log.Printf("Received policy update: %s\n", rule.Name)
		l.onUpdate(rule)
	})
	if err != nil {
		return err
	}
	
	// listen for policy deletions
	err = messaging.Subscribe("policy.delete", func(data []byte) {
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