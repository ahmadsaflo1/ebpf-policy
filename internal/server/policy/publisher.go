package policy

import (
	"encoding/json"
	"log"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

const (
	TopicPolicyUpdates = "policy.update"
	TopicPolicyDelete  = "policy.delete"
)

// Publish that a rule has been created or updated
func PublishUpdate(rule models.PolicyRule) {
	data, err := json.Marshal(rule)
	if err != nil {
		log.Println("Could not serialize rule:", err)
		return
	}

	err = messaging.Publish(TopicPolicyUpdates, data)
	if err != nil {
		log.Println("Could not publish policy update:", err)
	}

	log.Printf("Published policy update: %s\n", rule.Name)
}

// Publish that a rule has been removed
func PublishDelete(ruleID int) {
	data, err := json.Marshal(map[string]int{"id": ruleID})
	if err != nil {
		log.Println("Could not serialize rule-id:", err)
		return
	}

	err = messaging.Publish(TopicPolicyDelete, data)
	if err != nil {
		log.Println("Could not publish policy delete:", err)
	}

	log.Printf("Published policy delete for rule ID: %d\n", ruleID)
}