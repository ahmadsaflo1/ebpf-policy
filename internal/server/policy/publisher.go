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

	// If the rule has a tag, publish to a specific topic for that tag
	topic := TopicPolicyUpdates
    if rule.Tag != "" {
        topic = TopicPolicyUpdates + "." + rule.Tag
    }

    err = messaging.Publish(topic, data)
    if err != nil {
        log.Println("Could not publish policy update:", err)
        return
    }

    log.Printf("Published policy update: %s (topic: %s)\n", rule.Name, topic)
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