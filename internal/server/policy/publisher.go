// Package policy publishes rule lifecycle events (create/update/delete) to
// NATS so that enforcement agents receive changes in real time.
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

// PublishUpdate serialises rule and publishes it to the appropriate NATS topic.
// Rules with a topic are published to "policy.update.<topic>"; untagged rules
// go to "policy.update" so all agents receive them.
func PublishUpdate(rule models.PolicyRule) {
	data, err := json.Marshal(rule)
	if err != nil {
		log.Println("Could not serialize rule:", err)
		return
	}

	topic := TopicPolicyUpdates
    if rule.Topic != "" {
        topic = TopicPolicyUpdates + "." + rule.Topic
    }

    err = messaging.Publish(topic, data)
    if err != nil {
        log.Println("Could not publish policy update:", err)
        return
    }

    log.Printf("Published policy update: %s (topic: %s)\n", rule.Name, topic)
}

// PublishDelete publishes the ID of the deleted rule to "policy.delete" (or
// "policy.delete.<topic>" for topic-scoped rules) so agents can remove it locally.
func PublishDelete(rule models.PolicyRule) {
	data, err := json.Marshal(map[string]int{"id": rule.ID})
	if err != nil {
		log.Println("Could not serialize rule-id:", err)
		return
	}

	topic := "policy.delete"
    if rule.Topic != "" {
        topic = "policy.delete." + rule.Topic
    }

	err = messaging.Publish(topic, data)
	if err != nil {
		log.Println("Could not publish policy delete:", err)
	}

	log.Printf("Published rule delete: %s (topic: %s)\n", rule.Name, topic)
}